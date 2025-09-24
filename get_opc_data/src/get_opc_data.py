"""
GetOPCData - Processor for reading values from OPC UA nodes.
Reads current or historical values from specified OPC UA nodes/tags.
"""
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

from nifiapi.flowfilesource import FlowFileSource, FlowFileSourceResult
from nifiapi.properties import PropertyDescriptor
from nifiapi.relationship import Relationship

# OPC UA imports with graceful fallback
try:
    from opcua import Client, Node
    from opcua.common.node import NodeClass
    from opcua.ua.uaerrors import UaError
except ImportError:
    # Will be handled at runtime with proper error messages
    Client = None
    Node = None
    NodeClass = None
    UaError = Exception

# Additional imports for inline utilities
import json
import csv  
import xml.etree.ElementTree as ET
import traceback
from io import StringIO


class OPCUAClient:
    """OPC UA client operations for processor"""
    
    def __init__(self, connection_config: Dict[str, Any]):
        """Initialize with connection configuration dictionary"""
        self.config = connection_config
        self.client: Optional[Client] = None
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def get_client(self) -> Client:
        """Get the OPC UA client, connecting if necessary"""
        if not self.client:
            self.connect()
        return self.client
    
    def connect(self):
        """Establish connection using configuration"""
        try:
            endpoint = self.config.get('endpoint')
            if not endpoint:
                raise ValueError("OPC UA Server Endpoint is required")
                
            # Create client
            self.client = Client(endpoint)
            
            # Configure security
            self._configure_security()
            
            # Configure authentication  
            self._configure_authentication()
            
            # Set timeout
            timeout = self.config.get('timeout', 30)
            self.client.session_timeout = timeout * 1000  # Convert to milliseconds
            
            # Connect
            self.client.connect()
            
            self.logger.info(f"Successfully connected to OPC UA server: {endpoint}")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to OPC UA server: {str(e)}")
            raise
            
    def disconnect(self):
        """Disconnect from OPC UA server"""
        if self.client:
            try:
                self.client.disconnect()
                self.logger.info("Disconnected from OPC UA server")
            except Exception as e:
                self.logger.error(f"Error during disconnect: {str(e)}")
            finally:
                self.client = None
                
    def _configure_security(self):
        """Configure security based on configuration"""
        if not self.client:
            return
            
        security_policy = self.config.get('security_policy', 'None')
        
        try:
            if security_policy == "Basic128Rsa15":
                from opcua.ua import MessageSecurityMode, SecurityPolicyType
                self.client.set_security(SecurityPolicyType.Basic128Rsa15_Sign, MessageSecurityMode.Sign)
            elif security_policy == "Basic256":
                from opcua.ua import MessageSecurityMode, SecurityPolicyType
                self.client.set_security(SecurityPolicyType.Basic256_Sign, MessageSecurityMode.Sign)
            elif security_policy == "Basic256Sha256":
                from opcua.ua import MessageSecurityMode, SecurityPolicyType
                self.client.set_security(SecurityPolicyType.Basic256Sha256_Sign, MessageSecurityMode.Sign)
            # Default "None" requires no additional configuration
            
            self.logger.debug(f"Security configured: {security_policy}")
            
        except Exception as e:
            self.logger.error(f"Failed to configure security: {str(e)}")
            raise
            
    def _configure_authentication(self):
        """Configure authentication based on configuration"""
        if not self.client:
            return
            
        auth_mode = self.config.get('auth_mode', 'Anonymous')
        
        try:
            if auth_mode == "Username/Password":
                username = self.config.get('username', '')
                password = self.config.get('password', '')
                if username:
                    self.client.set_user(username)
                    if password:
                        self.client.set_password(password)
            elif auth_mode == "Certificate":
                cert_path = self.config.get('cert_path', '')
                key_path = self.config.get('key_path', '')
                if cert_path and key_path:
                    self.client.load_client_certificate(cert_path)
                    self.client.load_private_key(key_path)
            # Default "Anonymous" requires no additional configuration
            
            self.logger.debug(f"Authentication configured: {auth_mode}")
            
        except Exception as e:
            self.logger.error(f"Failed to configure authentication: {str(e)}")
            raise

    def read_values(self, node_ids: List[str], max_age: int = 0) -> Dict[str, Any]:
        """Read current values from specified OPC UA nodes"""
        try:
            client = self.get_client()
            results = {}
            
            for node_id in node_ids:
                try:
                    # Get node reference
                    node = client.get_node(node_id)
                    
                    # Read value with timestamp and quality
                    data_value = node.get_data_value()
                    
                    # Get display name
                    try:
                        display_name = node.get_display_name().Text
                    except:
                        display_name = node_id
                    
                    # Get data type
                    try:
                        data_type = str(node.get_data_type_as_variant_type())
                    except:
                        data_type = "Unknown"
                    
                    # Build result
                    result = {
                        "node_id": node_id,
                        "display_name": display_name,
                        "value": data_value.Value.Value if data_value.Value else None,
                        "data_type": data_type,
                        "server_timestamp": data_value.ServerTimestamp.isoformat() if data_value.ServerTimestamp else None,
                        "source_timestamp": data_value.SourceTimestamp.isoformat() if data_value.SourceTimestamp else None,
                        "quality": {
                            "code": data_value.StatusCode.name if hasattr(data_value.StatusCode, 'name') else str(data_value.StatusCode),
                            "numeric_code": data_value.StatusCode.value if hasattr(data_value.StatusCode, 'value') else 0,
                            "description": self._get_quality_description(data_value.StatusCode)
                        },
                        "status": "Success"
                    }
                    
                    results[node_id] = result
                    
                except Exception as e:
                    # Handle individual node read failures
                    results[node_id] = {
                        "node_id": node_id,
                        "display_name": node_id,
                        "value": None,
                        "data_type": "Unknown",
                        "server_timestamp": datetime.now().isoformat(),
                        "source_timestamp": None,
                        "quality": {
                            "code": "Bad_NodeIdUnknown",
                            "numeric_code": 2149580800,
                            "description": "The node id refers to a node that does not exist"
                        },
                        "status": "Failed",
                        "error_message": str(e)
                    }
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Error reading values: {str(e)}")
            raise
    
    def _get_quality_description(self, status_code) -> str:
        """Get human-readable description for status code"""
        try:
            if hasattr(status_code, 'name'):
                name = status_code.name
                if name.startswith('Good'):
                    return "The value is good"
                elif name.startswith('Bad'):
                    return "The server cannot obtain the value"
                elif name.startswith('Uncertain'):
                    return "The value is uncertain"
                else:
                    return f"Status: {name}"
            else:
                return f"Status code: {status_code}"
        except:
            return "Unknown status"

    def get_server_info(self) -> Dict[str, Any]:
        """Get OPC UA server information"""
        try:
            client = self.get_client()
            
            # Get server info
            server_info = {
                "endpoint_url": self.config.get('endpoint', 'Unknown'),
                "session_timeout": getattr(client, 'session_timeout', 0),
                "secure_channel_timeout": getattr(client, 'secure_channel_timeout', 0)
            }
            
            # Try to get server status
            try:
                server_node = client.get_server_node()
                server_info["server_name"] = server_node.get_display_name().Text
            except:
                server_info["server_name"] = "Unknown"
                
            # Try to get application URI
            try:
                server_info["application_uri"] = getattr(client, 'application_uri', 'Unknown')
            except:
                server_info["application_uri"] = "Unknown"
                
            return server_info
            
        except Exception as e:
            self.logger.error(f"Error getting server info: {e}")
            return {
                "endpoint_url": self.config.get('endpoint', 'Unknown'),
                "server_name": "Unknown", 
                "application_uri": "Unknown",
                "error": str(e)
            }


class DataFormatters:
    """Utility class for formatting OPC UA data in different output formats"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def format_data_values(self, data_points: Dict[str, Any],
                          server_info: Dict[str, Any], 
                          read_params: Dict[str, Any],
                          summary: Dict[str, Any],
                          output_format: str = "JSON") -> bytes:
        """Format data values in the specified format"""
        timestamp = datetime.now().isoformat() + "Z"
        
        # Convert data_points dict to list for consistent formatting
        data_points_list = list(data_points.values()) if isinstance(data_points, dict) else data_points
        
        # Create complete data structure
        data = {
            "read_timestamp": timestamp,
            "server_info": server_info,
            "read_parameters": read_params,
            "data_points": data_points_list,
            "summary": summary,
            "read_duration_ms": 0  # Will be set by processor
        }
        
        if output_format.upper() == "JSON":
            return self._format_json(data)
        elif output_format.upper() == "CSV":
            return self._format_values_csv(data_points_list)
        elif output_format.upper() == "XML":
            return self._format_values_xml(data)
        else:
            # Default to JSON
            return self._format_json(data)

    def _format_json(self, data: Dict[str, Any]) -> bytes:
        """Format data as JSON"""
        try:
            json_str = json.dumps(data, indent=2, default=self._json_serializer)
            return json_str.encode('utf-8')
        except Exception as e:
            self.logger.error(f"Error formatting JSON: {e}")
            # Return error structure
            error_data = {
                "error": "JSON formatting failed",
                "message": str(e),
                "timestamp": datetime.now().isoformat() + "Z"
            }
            return json.dumps(error_data).encode('utf-8')
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for complex objects"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)

    def _format_values_csv(self, data_points: List[Dict[str, Any]]) -> bytes:
        """Format data values as CSV"""
        try:
            output = StringIO()
            
            if not data_points:
                return b"node_id,display_name,value,data_type,server_timestamp,source_timestamp,quality_code,status\n"
            
            # Standard columns for values CSV
            columns = [
                "node_id", "display_name", "value", "data_type",
                "server_timestamp", "source_timestamp", "quality_code", "quality_description", "status"
            ]
            
            writer = csv.DictWriter(output, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            
            for data_point in data_points:
                # Flatten quality information
                row = dict(data_point)
                if 'quality' in row and isinstance(row['quality'], dict):
                    quality = row['quality']
                    row['quality_code'] = quality.get('code', 'Unknown')
                    row['quality_description'] = quality.get('description', 'Unknown')
                    del row['quality']
                
                writer.writerow(row)
            
            return output.getvalue().encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error formatting values CSV: {e}")
            error_csv = f"error,message\nCSV formatting failed,{str(e)}\n"
            return error_csv.encode('utf-8')

    def _format_values_xml(self, data: Dict[str, Any]) -> bytes:
        """Format data values as XML"""
        try:
            root = ET.Element("opcua_data_values")
            
            # Add metadata
            metadata = ET.SubElement(root, "metadata")
            ET.SubElement(metadata, "read_timestamp").text = str(data.get("read_timestamp", ""))
            ET.SubElement(metadata, "read_duration_ms").text = str(data.get("read_duration_ms", 0))
            
            # Add server info
            server_info = ET.SubElement(metadata, "server_info")
            server_data = data.get("server_info", {})
            for key, value in server_data.items():
                ET.SubElement(server_info, key).text = str(value)
            
            # Add read parameters
            read_params = ET.SubElement(metadata, "read_parameters") 
            param_data = data.get("read_parameters", {})
            for key, value in param_data.items():
                ET.SubElement(read_params, key).text = str(value)
            
            # Add summary
            summary = ET.SubElement(metadata, "summary")
            summary_data = data.get("summary", {})
            for key, value in summary_data.items():
                ET.SubElement(summary, key).text = str(value)
            
            # Add data points
            data_points_elem = ET.SubElement(root, "data_points")
            for data_point in data.get("data_points", []):
                point_elem = ET.SubElement(data_points_elem, "data_point")
                for key, value in data_point.items():
                    if isinstance(value, dict):
                        # Handle nested dictionaries (like quality)
                        nested_elem = ET.SubElement(point_elem, key)
                        for nested_key, nested_value in value.items():
                            ET.SubElement(nested_elem, nested_key).text = str(nested_value)
                    else:
                        ET.SubElement(point_elem, key).text = str(value) if value is not None else ""
            
            return ET.tostring(root, encoding='utf-8', xml_declaration=True)
            
        except Exception as e:
            self.logger.error(f"Error formatting XML: {e}")
            error_root = ET.Element("error")
            ET.SubElement(error_root, "message").text = f"XML formatting failed: {str(e)}"
            ET.SubElement(error_root, "timestamp").text = datetime.now().isoformat()
            return ET.tostring(error_root, encoding='utf-8', xml_declaration=True)


class OPCUAErrorHandler:
    """Centralized error handling for OPC UA processors"""
    
    def __init__(self, processor_name: str):
        self.processor_name = processor_name
        self.logger = logging.getLogger(f"{processor_name}.ErrorHandler")
    
    def handle_connection_error(self, error: Exception, context: Dict[str, Any] = None) -> FlowFileSourceResult:
        """Handle OPC UA connection-related errors"""
        error_msg = str(error)
        error_type = "ConnectionError"
        
        # Categorize common connection errors
        if "timeout" in error_msg.lower():
            error_type = "TimeoutError"
            user_message = "Connection to OPC UA server timed out. Check server availability and network connectivity."
        elif "refused" in error_msg.lower() or "unreachable" in error_msg.lower():
            error_type = "NetworkError"  
            user_message = "Unable to reach OPC UA server. Verify server endpoint URL and network connectivity."
        elif "authentication" in error_msg.lower() or "unauthorized" in error_msg.lower():
            error_type = "AuthenticationError"
            user_message = "Authentication failed. Check username, password, and certificate configuration."
        elif "certificate" in error_msg.lower() or "ssl" in error_msg.lower():
            error_type = "SecurityError"
            user_message = "Security/Certificate error. Verify certificate configuration and trust settings."
        else:
            user_message = f"Connection error: {error_msg}"
        
        # Log the error
        self.logger.error(f"{error_type} in {self.processor_name}: {error_msg}")
        if context:
            self.logger.debug(f"Error context: {context}")
        
        # Build error attributes
        attributes = {
            "opcua.error.type": error_type,
            "opcua.error.message": error_msg,
            "opcua.error.user_message": user_message,
            "opcua.error.processor": self.processor_name,
            "opcua.error.timestamp": datetime.now().isoformat() + "Z"
        }
        
        # Add context attributes
        if context:
            for key, value in context.items():
                attributes[f"opcua.context.{key}"] = str(value)
        
        return FlowFileSourceResult(
            relationship="failure",
            attributes=attributes,
            contents=self._create_error_content(error_type, error_msg, user_message, context)
        )
    
    def create_no_data_result(self, reason: str, context: Dict[str, Any] = None) -> FlowFileSourceResult:
        """Create result for no data scenarios"""
        attributes = {
            "opcua.no_data.reason": reason,
            "opcua.no_data.processor": self.processor_name,
            "opcua.no_data.timestamp": datetime.now().isoformat() + "Z"
        }
        
        if context:
            for key, value in context.items():
                attributes[f"opcua.context.{key}"] = str(value)
        
        content = {
            "no_data": {
                "reason": reason,
                "processor": self.processor_name,
                "timestamp": datetime.now().isoformat() + "Z",
                "context": context or {}
            }
        }
        
        return FlowFileSourceResult(
            relationship="empty",
            attributes=attributes,
            contents=json.dumps(content, indent=2).encode('utf-8')
        )
    
    def _create_error_content(self, error_type: str, error_msg: str, user_message: str, context: Dict[str, Any] = None) -> bytes:
        """Create JSON error content for FlowFile"""
        error_content = {
            "error": {
                "type": error_type,
                "message": error_msg,
                "user_message": user_message,
                "processor": self.processor_name,
                "timestamp": datetime.now().isoformat() + "Z"
            }
        }
        
        if context:
            error_content["context"] = context
        
        # Add stack trace for debugging (truncated)
        try:
            error_content["debug"] = {
                "stack_trace": traceback.format_exc()[:1000] + "..." if len(traceback.format_exc()) > 1000 else traceback.format_exc()
            }
        except:
            pass
        
        return json.dumps(error_content, indent=2).encode('utf-8')


def handle_opcua_exception(processor_name: str, error: Exception, context: Dict[str, Any] = None) -> FlowFileSourceResult:
    """Convenience function to handle any OPC UA exception"""
    handler = OPCUAErrorHandler(processor_name)
    
    # Route to appropriate handler based on error type/message
    error_msg = str(error).lower()
    
    if any(keyword in error_msg for keyword in ["connection", "timeout", "refused", "unreachable", "authentication", "certificate", "ssl"]):
        return handler.handle_connection_error(error, context)
    else:
        # Generic error handling
        return handler.handle_connection_error(error, context)


class GetOPCData(FlowFileSource):
    """
    Processor that reads current values from specified OPC UA nodes/tags.
    Supports various timestamp options, quality filtering, and multiple output formats.
    """
    
    class Java:
        implements = ['org.apache.nifi.python.processor.FlowFileSource']
    
    class ProcessorDetails:
        version = '1.0.0'
        description = 'Reads current values from specified OPC UA nodes with configurable quality filtering and timestamp selection'
        tags = ['OPC UA', 'Read', 'Data', 'Industrial IoT', 'SCADA', 'Tags', 'Values']
        dependencies = [
            "opcua>=0.98.13",
            "cryptography>=3.4.8"
        ]
    
    def __init__(self, **kwargs):
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.error_handler = OPCUAErrorHandler("GetOPCData")
        self.data_formatter = DataFormatters()
    
    def getPropertyDescriptors(self):
        """Define configuration properties for the processor"""
        return [
            # OPC UA Connection Properties  
            PropertyDescriptor(
                name="OPC UA Server Endpoint",
                description="OPC UA server endpoint URL (e.g., opc.tcp://localhost:4840)",
                required=True
            ),
            PropertyDescriptor(
                name="Security Policy",
                description="Security policy for OPC UA connection",
                default_value="None",
                allowable_values=["None", "Basic128Rsa15", "Basic256", "Basic256Sha256"]
            ),
            PropertyDescriptor(
                name="Authentication Mode",
                description="Authentication method for OPC UA connection",
                default_value="Anonymous",
                allowable_values=["Anonymous", "Username/Password", "Certificate"]
            ),
            PropertyDescriptor(
                name="Username",
                description="Username for authentication (when using Username/Password mode)",
                default_value=""
            ),
            PropertyDescriptor(
                name="Password",
                description="Password for authentication (when using Username/Password mode)",
                default_value="",
                sensitive=True
            ),
            PropertyDescriptor(
                name="Connection Timeout",
                description="Connection timeout in seconds",
                default_value="30"
            ),
            PropertyDescriptor(
                name="Node IDs",
                description="Comma-separated list of OPC UA Node IDs to read (e.g., ns=2;s=Temperature1,ns=2;s=Pressure1)",
                required=True
            ),
            PropertyDescriptor(
                name="Read Mode",
                description="How to read the node values",
                default_value="Current",
                allowable_values=["Current", "Historical"]
            ),
            PropertyDescriptor(
                name="Timestamp Selection",
                description="Which timestamp to use for data points",
                default_value="Server",
                allowable_values=["Server", "Source", "Both"]
            ),
            PropertyDescriptor(
                name="Exclude Null Values",
                description="Exclude nodes with null/bad quality values from output",
                default_value="true",
                allowable_values=["true", "false"]
            ),
            PropertyDescriptor(
                name="Include Quality Info",
                description="Include OPC UA quality information in output",
                default_value="true",
                allowable_values=["true", "false"]
            ),
            PropertyDescriptor(
                name="Output Format",
                description="Format for data output",
                default_value="JSON",
                allowable_values=["JSON", "CSV", "XML"]
            ),
            PropertyDescriptor(
                name="Max Age",
                description="Maximum age of cached values to accept (seconds, 0=no limit)",
                default_value="0"
            ),
            PropertyDescriptor(
                name="Batch Size",
                description="Maximum number of nodes to read in a single batch (0=read all at once)",
                default_value="100"
            ),
            
            # Historical read properties (when Read Mode = Historical)
            PropertyDescriptor(
                name="Start Time",
                description="Start time for historical data (ISO format: 2024-12-15T10:00:00Z, or relative: -1h)",
                default_value=""
            ),
            PropertyDescriptor(
                name="End Time",
                description="End time for historical data (ISO format: 2024-12-15T11:00:00Z, or relative: -30m)",
                default_value=""
            ),
            PropertyDescriptor(
                name="Processing Interval",
                description="Interval for historical data aggregation (milliseconds)",
                default_value="1000"
            ),
            PropertyDescriptor(
                name="Max Historical Points",
                description="Maximum number of historical data points per node (0=no limit)",
                default_value="1000"
            )
        ]
    
    def getRelationships(self):
        """Define output relationships for the processor"""
        return [
            Relationship("success", "Successfully read data from OPC UA server"),
            Relationship("failure", "Failed to read data from OPC UA server"),
            Relationship("partial_success", "Some nodes read successfully, others failed"),
            Relationship("no_data", "No valid data found (all null or bad quality)")
        ]
    
    def create(self, context):
        """Main processor logic - read values from OPC UA nodes"""
        start_time = time.time()
        
        try:
            # Get configuration properties
            config = self._get_configuration(context)
            
            # Validate configuration
            self._validate_configuration(config)
            
            # Parse node IDs
            node_ids = self._parse_node_ids(config['node_ids'])
            
            # Extract connection configuration
            connection_config = self._get_connection_config(context)
            
            # Create OPC UA client
            client = OPCUAClient(connection_config)
            
            # Read values based on mode
            if config['read_mode'] == "Historical":
                data_points, summary = self._read_historical_data(client, node_ids, config)
            else:
                data_points, summary = self._read_current_data(client, node_ids, config)
            
            # Apply quality filtering
            if config['exclude_null_values']:
                filtered_data = self._filter_null_values(data_points)
                summary['null_values_excluded'] = len(data_points) - len(filtered_data)
                data_points = filtered_data
            else:
                summary['null_values_excluded'] = 0
            
            # Check if any valid data remains
            if not data_points:
                return self.error_handler.create_no_data_result(
                    reason="No valid data found after filtering",
                    context={
                        "node_ids": config['node_ids'],
                        "exclude_null_values": config['exclude_null_values'],
                        "total_requested": summary.get('total_requested', 0)
                    }
                )
            
            # Get server information
            server_info = client.get_server_info()
            
            # Prepare read parameters for output
            read_params = {
                "read_mode": config['read_mode'],
                "timestamp_selection": config['timestamp_selection'],
                "exclude_null_values": config['exclude_null_values'],
                "include_quality_info": config['include_quality_info'],
                "max_age_seconds": config['max_age']
            }
            
            if config['read_mode'] == "Historical":
                read_params.update({
                    "start_time": config['start_time'],
                    "end_time": config['end_time'],
                    "processing_interval": config['processing_interval'],
                    "max_historical_points": config['max_historical_points']
                })
            
            # Calculate duration
            read_duration = int((time.time() - start_time) * 1000)
            summary['read_duration_ms'] = read_duration
            
            # Format output
            content = self.data_formatter.format_data_values(
                data_points=data_points,
                server_info=server_info,
                read_params=read_params,
                summary=summary,
                output_format=config['output_format']
            )
            
            # Update content with actual read duration
            if config['output_format'].upper() == "JSON":
                import json
                try:
                    data = json.loads(content.decode('utf-8'))
                    data['read_duration_ms'] = read_duration
                    content = json.dumps(data, indent=2).encode('utf-8')
                except:
                    pass  # Keep original content if JSON parsing fails
            
            # Determine relationship based on results
            relationship = "success"
            if summary['failed_reads'] > 0:
                if summary['successful_reads'] > 0:
                    relationship = "partial_success"
                else:
                    relationship = "failure"
            
            # Create success attributes
            attributes = {
                "opcua.read.total_requested": str(summary['total_requested']),
                "opcua.read.successful": str(summary['successful_reads']),
                "opcua.read.failed": str(summary['failed_reads']),
                "opcua.read.null_excluded": str(summary['null_values_excluded']),
                "opcua.read.mode": config['read_mode'],
                "opcua.read.timestamp_selection": config['timestamp_selection'],
                "opcua.read.exclude_null_values": str(config['exclude_null_values']),
                "opcua.read.include_quality_info": str(config['include_quality_info']),
                "opcua.read.output_format": config['output_format'],
                "opcua.read.duration_ms": str(read_duration),
                "opcua.server.endpoint": server_info.get('endpoint_url', 'Unknown'),
                "opcua.server.name": server_info.get('server_name', 'Unknown'),
                "mime.type": self._get_mime_type(config['output_format'])
            }
            
            # Add node ID list for reference
            if len(config['node_ids']) < 1000:  # Avoid huge attribute values
                attributes["opcua.read.node_ids"] = config['node_ids']
            
            self.logger.info(f"Successfully read {summary['successful_reads']}/{summary['total_requested']} nodes in {read_duration}ms")
            
            return FlowFileSourceResult(
                relationship=relationship,
                attributes=attributes,
                contents=content
            )
            
        except Exception as e:
            self.logger.error(f"Error reading OPC UA data: {str(e)}")
            # Initialize config if error occurred before config was set
            try:
                error_context = {
                    "node_ids": config.get('node_ids', 'Unknown'),
                    "read_mode": config.get('read_mode', 'Unknown'),
                    "node_count": len(self._parse_node_ids(config.get('node_ids', ''))) if config.get('node_ids') else 0
                }
            except NameError:
                error_context = {
                    "node_ids": "Unknown",
                    "read_mode": "Unknown",
                    "node_count": 0
                }
            return handle_opcua_exception("GetOPCData", e, error_context)
    
    def _get_configuration(self, context) -> Dict[str, Any]:
        """Extract and parse configuration properties"""
        try:
            config = {
                'node_ids': self._get_property_value(context, "Node IDs", "").strip(),
                'read_mode': self._get_property_value(context, "Read Mode", "Current"),
                'timestamp_selection': self._get_property_value(context, "Timestamp Selection", "Server"),
                'exclude_null_values': self._get_property_value(context, "Exclude Null Values", "true").lower() == "true",
                'include_quality_info': self._get_property_value(context, "Include Quality Info", "true").lower() == "true",
                'output_format': self._get_property_value(context, "Output Format", "JSON"),
                'max_age': int(self._get_property_value(context, "Max Age", "0")),
                'batch_size': int(self._get_property_value(context, "Batch Size", "100")),
                
                # Historical properties
                'start_time': self._get_property_value(context, "Start Time", "").strip(),
                'end_time': self._get_property_value(context, "End Time", "").strip(),
                'processing_interval': int(self._get_property_value(context, "Processing Interval", "1000")),
                'max_historical_points': int(self._get_property_value(context, "Max Historical Points", "1000"))
            }
            return config
            
        except ValueError as e:
            raise ValueError(f"Invalid configuration value: {str(e)}")
        except Exception as e:
            raise Exception(f"Error reading configuration: {str(e)}")
    
    def _get_property_value(self, context, property_name: str, default_value: str) -> str:
        """Safely get property value with fallback"""
        try:
            prop = context.getProperty(property_name)
            return prop.getValue() if prop and prop.getValue() else default_value
        except Exception as e:
            self.logger.debug(f"Error getting property '{property_name}': {e}")
            return default_value
    
    def _validate_configuration(self, config: Dict[str, Any]):
        """Validate configuration values"""
        # Validate node IDs
        if not config['node_ids']:
            raise ValueError("Node IDs cannot be empty")
        
        # Validate max age
        if config['max_age'] < 0:
            raise ValueError("Max Age cannot be negative")
        
        # Validate batch size
        if config['batch_size'] < 0:
            raise ValueError("Batch Size cannot be negative")
        
        # Validate historical properties if historical mode
        if config['read_mode'] == "Historical":
            if config['processing_interval'] <= 0:
                raise ValueError("Processing Interval must be positive")
            
            if config['max_historical_points'] < 0:
                raise ValueError("Max Historical Points cannot be negative")
    
    def _parse_node_ids(self, node_ids_str: str) -> List[str]:
        """Parse comma-separated node IDs"""
        if not node_ids_str:
            return []
        
        # Split by comma and clean up
        node_ids = [node_id.strip() for node_id in node_ids_str.split(',')]
        node_ids = [node_id for node_id in node_ids if node_id]  # Remove empty strings
        
        if not node_ids:
            raise ValueError("No valid node IDs found")
        
        # Basic validation of node ID format
        for node_id in node_ids:
            if not (node_id.startswith('ns=') or node_id.startswith('i=') or node_id.startswith('s=')):
                raise ValueError(f"Invalid node ID format: {node_id}. Expected format like 'ns=2;s=TagName' or 'ns=0;i=2256'")
        
        return node_ids
    
    def _get_connection_config(self, context) -> Dict[str, Any]:
        """Extract connection configuration from processor properties"""
        try:
            connection_config = {
                'endpoint': self._get_property_value(context, "OPC UA Server Endpoint", ""),
                'security_policy': self._get_property_value(context, "Security Policy", "None"),
                'auth_mode': self._get_property_value(context, "Authentication Mode", "Anonymous"),
                'username': self._get_property_value(context, "Username", ""),
                'password': self._get_property_value(context, "Password", ""),
                'timeout': int(self._get_property_value(context, "Connection Timeout", "30"))
            }
            
            # Validate required fields
            if not connection_config['endpoint']:
                raise ValueError("OPC UA Server Endpoint is required")
                
            return connection_config
            
        except Exception as e:
            raise Exception(f"Failed to get connection configuration: {str(e)}")
    
    def _read_current_data(self, client: OPCUAClient, node_ids: List[str], config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """Read current values from nodes"""
        try:
            # Read values using the client
            results = client.read_values(node_ids, config['max_age'])
            
            # Calculate summary statistics
            successful_reads = sum(1 for result in results.values() if result.get('status') == 'Success')
            failed_reads = len(results) - successful_reads
            
            summary = {
                'total_requested': len(node_ids),
                'successful_reads': successful_reads,
                'failed_reads': failed_reads
            }
            
            return results, summary
            
        except Exception as e:
            self.logger.error(f"Error reading current data: {str(e)}")
            raise
    
    def _read_historical_data(self, client: OPCUAClient, node_ids: List[str], config: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
        """Read historical values from nodes"""
        # For this implementation, we'll fall back to current values
        # Real historical reading would require additional OPC UA client methods
        self.logger.warning("Historical mode not fully implemented, falling back to current values")
        
        return self._read_current_data(client, node_ids, config)
    
    def _filter_null_values(self, data_points: Dict[str, Any]) -> Dict[str, Any]:
        """Filter out null or bad quality values"""
        filtered = {}
        
        for node_id, data in data_points.items():
            # Keep data point if:
            # 1. Value is not None
            # 2. Quality is good (starts with "Good")
            # 3. Status is Success
            if (data.get('value') is not None and 
                data.get('quality', {}).get('code', '').startswith('Good') and
                data.get('status') == 'Success'):
                filtered[node_id] = data
        
        return filtered
    
    def _parse_relative_time(self, time_str: str) -> datetime:
        """Parse relative time expressions like -1h, -30m"""
        if not time_str.startswith('-'):
            # Try to parse as absolute time
            return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
        
        # Parse relative time
        time_str = time_str[1:]  # Remove minus sign
        
        if time_str.endswith('h'):
            hours = int(time_str[:-1])
            return datetime.now() - timedelta(hours=hours)
        elif time_str.endswith('m'):
            minutes = int(time_str[:-1])
            return datetime.now() - timedelta(minutes=minutes)
        elif time_str.endswith('s'):
            seconds = int(time_str[:-1])
            return datetime.now() - timedelta(seconds=seconds)
        else:
            raise ValueError(f"Invalid relative time format: -{time_str}")
    
    def _get_mime_type(self, output_format: str) -> str:
        """Get MIME type based on output format"""
        format_mime_types = {
            "JSON": "application/json",
            "CSV": "text/csv",
            "XML": "application/xml"
        }
        return format_mime_types.get(output_format.upper(), "application/octet-stream")
