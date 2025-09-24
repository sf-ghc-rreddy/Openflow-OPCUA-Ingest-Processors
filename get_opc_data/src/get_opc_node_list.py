"""
GetOPCNodeList - Processor for discovering and listing OPC UA nodes.
Browses the OPC UA server namespace to discover available tags and their metadata.
"""
import time
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

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

    def browse_nodes(self, start_node: str, max_depth: int = 10, 
                    node_class_filter: str = "Variable", 
                    include_system: bool = False) -> List[Dict[str, Any]]:
        """Browse OPC UA server namespace to discover nodes"""
        try:
            client = self.get_client()
            nodes = []
            
            # Get starting node
            if start_node.startswith('ns='):
                root_node = client.get_node(start_node)
            else:
                # Default to Objects folder if not fully qualified
                root_node = client.get_objects_node()
            
            # Browse recursively
            self._browse_recursive(
                node=root_node,
                nodes=nodes,
                current_depth=0,
                max_depth=max_depth,
                node_class_filter=node_class_filter,
                include_system=include_system,
                path=""
            )
            
            return nodes
            
        except Exception as e:
            self.logger.error(f"Error browsing nodes: {str(e)}")
            raise

    def _browse_recursive(self, node: Node, nodes: List[Dict], 
                         current_depth: int, max_depth: int,
                         node_class_filter: str, include_system: bool,
                         path: str):
        """Recursively browse nodes"""
        try:
            # Check depth limit
            if max_depth > 0 and current_depth >= max_depth:
                return
                
            # Get node children
            children = node.get_children()
            
            for child in children:
                try:
                    # Get node attributes
                    node_id = child.nodeid.to_string()
                    display_name = child.get_display_name().Text
                    node_class = child.get_node_class()
                    
                    # Skip system nodes if not included
                    if not include_system and self._is_system_node(node_id, display_name):
                        continue
                    
                    # Apply node class filter
                    if not self._passes_node_filter(node_class, node_class_filter):
                        continue
                        
                    # Build browse path
                    current_path = f"{path}.{display_name}" if path else display_name
                    
                    # Get additional attributes for variables
                    node_info = {
                        "node_id": node_id,
                        "display_name": display_name,
                        "node_class": node_class.name,
                        "browse_path": current_path,
                        "parent_node_id": node.nodeid.to_string() if node else None,
                        "has_children": len(child.get_children()) > 0
                    }
                    
                    # Add variable-specific attributes
                    if node_class == NodeClass.Variable:
                        try:
                            data_type = child.get_data_type_as_variant_type()
                            node_info.update({
                                "data_type": str(data_type),
                                "access_level": self._get_access_level(child),
                                "attributes": self._get_variable_attributes(child)
                            })
                        except Exception as e:
                            self.logger.debug(f"Could not get variable attributes for {node_id}: {e}")
                            node_info["data_type"] = "Unknown"
                            node_info["access_level"] = "Unknown"
                            node_info["attributes"] = {}
                    
                    nodes.append(node_info)
                    
                    # Recurse into children if not at max depth
                    if max_depth == 0 or current_depth < max_depth - 1:
                        self._browse_recursive(
                            child, nodes, current_depth + 1, max_depth,
                            node_class_filter, include_system, current_path
                        )
                        
                except Exception as e:
                    self.logger.debug(f"Error processing child node: {e}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error in recursive browse: {e}")
            
    def _is_system_node(self, node_id: str, display_name: str) -> bool:
        """Check if node is a system node"""
        system_patterns = [
            "Server", "ServerCapabilities", "ServerDiagnostics",
            "VendorServerInfo", "ServerRedundancy", "Namespaces"
        ]
        return any(pattern in display_name for pattern in system_patterns) or node_id.startswith("ns=0;i=")
    
    def _passes_node_filter(self, node_class: NodeClass, filter_type: str) -> bool:
        """Check if node passes the class filter"""
        if filter_type == "All":
            return True
        try:
            filter_class = getattr(NodeClass, filter_type)
            return node_class == filter_class
        except AttributeError:
            return True
    
    def _get_access_level(self, node: Node) -> str:
        """Get access level for variable node"""
        try:
            access_level = node.get_access_level()
            if access_level == 1:
                return "CurrentRead"
            elif access_level == 2:
                return "CurrentWrite" 
            elif access_level == 3:
                return "CurrentReadWrite"
            else:
                return f"AccessLevel_{access_level}"
        except:
            return "Unknown"
    
    def _get_variable_attributes(self, node: Node) -> Dict[str, Any]:
        """Get additional attributes for variable nodes"""
        attributes = {}
        try:
            # Try to get description
            try:
                desc = node.get_description()
                if desc and desc.Text:
                    attributes["description"] = desc.Text
            except:
                pass
                
            # Try to get value rank
            try:
                attributes["value_rank"] = node.get_value_rank()
            except:
                pass
                
        except Exception as e:
            self.logger.debug(f"Error getting variable attributes: {e}")
            
        return attributes

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
    
    def format_node_list(self, nodes: List[Dict[str, Any]], 
                        server_info: Dict[str, Any],
                        browse_params: Dict[str, Any],
                        output_format: str = "JSON") -> bytes:
        """Format node list data in the specified format"""
        timestamp = datetime.now().isoformat() + "Z"
        
        # Create complete data structure
        data = {
            "browse_timestamp": timestamp,
            "server_info": server_info,
            "browse_parameters": browse_params,
            "nodes": nodes,
            "total_nodes_found": len(nodes),
            "browse_duration_ms": 0  # Will be set by processor
        }
        
        if output_format.upper() == "JSON":
            return self._format_json(data)
        elif output_format.upper() == "CSV":
            return self._format_nodes_csv(nodes)
        elif output_format.upper() == "XML":
            return self._format_nodes_xml(data)
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
    
    def _format_nodes_csv(self, nodes: List[Dict[str, Any]]) -> bytes:
        """Format node list as CSV"""
        try:
            output = StringIO()
            
            if not nodes:
                return b"node_id,display_name,node_class,data_type,browse_path\n"
            
            # Determine CSV columns based on available data
            columns = [
                "node_id", "display_name", "node_class", "data_type", 
                "access_level", "browse_path", "parent_node_id", "has_children"
            ]
            
            writer = csv.DictWriter(output, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            
            for node in nodes:
                # Flatten nested attributes
                row = dict(node)
                if 'attributes' in row and isinstance(row['attributes'], dict):
                    # Add key attributes as separate columns
                    for key, value in row['attributes'].items():
                        if key in ['description', 'value_rank']:
                            row[f"attr_{key}"] = value
                    del row['attributes']
                
                writer.writerow(row)
            
            return output.getvalue().encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Error formatting CSV: {e}")
            error_csv = f"error,message\nCSV formatting failed,{str(e)}\n"
            return error_csv.encode('utf-8')
    
    def _format_nodes_xml(self, data: Dict[str, Any]) -> bytes:
        """Format node list as XML"""
        try:
            root = ET.Element("opcua_node_list")
            
            # Add metadata
            metadata = ET.SubElement(root, "metadata")
            ET.SubElement(metadata, "browse_timestamp").text = str(data.get("browse_timestamp", ""))
            ET.SubElement(metadata, "total_nodes_found").text = str(data.get("total_nodes_found", 0))
            
            # Add server info
            server_info = ET.SubElement(metadata, "server_info")
            server_data = data.get("server_info", {})
            for key, value in server_data.items():
                ET.SubElement(server_info, key).text = str(value)
            
            # Add browse parameters
            browse_params = ET.SubElement(metadata, "browse_parameters") 
            param_data = data.get("browse_parameters", {})
            for key, value in param_data.items():
                ET.SubElement(browse_params, key).text = str(value)
            
            # Add nodes
            nodes_elem = ET.SubElement(root, "nodes")
            for node in data.get("nodes", []):
                node_elem = ET.SubElement(nodes_elem, "node")
                for key, value in node.items():
                    if isinstance(value, dict):
                        # Handle nested dictionaries (like attributes)
                        nested_elem = ET.SubElement(node_elem, key)
                        for nested_key, nested_value in value.items():
                            ET.SubElement(nested_elem, nested_key).text = str(nested_value)
                    else:
                        ET.SubElement(node_elem, key).text = str(value) if value is not None else ""
            
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


class GetOPCNodeList(FlowFileSource):
    """
    Processor that browses the OPC UA server namespace to discover available nodes (tags)
    and their metadata information.
    """
    
    class Java:
        implements = ['org.apache.nifi.python.processor.FlowFileSource']
    
    class ProcessorDetails:
        version = '1.0.0'
        description = 'Browses OPC UA server namespace to discover available nodes and their metadata'
        tags = ['OPC UA', 'Browse', 'Discovery', 'Industrial IoT', 'SCADA', 'Tags']
        dependencies = [
            "opcua>=0.98.13",
            "cryptography>=3.4.8"
        ]
    
    def __init__(self, **kwargs):
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.error_handler = OPCUAErrorHandler("GetOPCNodeList")
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
                name="Starting Node ID",
                description="Root node ID to start browsing from (default: Objects folder ns=0;i=85)",
                default_value="ns=0;i=85"
            ),
            PropertyDescriptor(
                name="Browse Depth",
                description="Maximum depth to browse from starting node (0 = unlimited, default: 10)",
                default_value="10"
            ),
            PropertyDescriptor(
                name="Node Class Filter",
                description="Filter nodes by class type",
                default_value="Variable",
                allowable_values=["Variable", "Object", "Method", "View", "All"]
            ),
            PropertyDescriptor(
                name="Include System Nodes",
                description="Include OPC UA system and server nodes in results",
                default_value="false",
                allowable_values=["true", "false"]
            ),
            PropertyDescriptor(
                name="Output Format",
                description="Format for the node list output",
                default_value="JSON",
                allowable_values=["JSON", "CSV", "XML"]
            ),
            PropertyDescriptor(
                name="Cache Duration",
                description="Duration to cache browse results in seconds (0 = no cache, default: 3600)",
                default_value="3600"
            ),
            PropertyDescriptor(
                name="Max Nodes Limit",
                description="Maximum number of nodes to include in output (0 = no limit, default: 10000)",
                default_value="10000"
            )
        ]
    
    def getRelationships(self):
        """Define output relationships for the processor"""
        return [
            Relationship("success", "Successfully retrieved node list from OPC UA server"),
            Relationship("failure", "Failed to retrieve node list from OPC UA server"),
            Relationship("empty", "No nodes found matching the specified criteria")
        ]
    
    def create(self, context):
        """Main processor logic - browse OPC UA server and return node list"""
        start_time = time.time()
        
        try:
            # Get configuration properties
            config = self._get_configuration(context)
            
            # Validate configuration
            self._validate_configuration(config)
            
            # Extract connection configuration
            connection_config = self._get_connection_config(context)
            
            # Check cache if enabled
            if config['cache_duration'] > 0:
                cached_result = self._check_cache(config)
                if cached_result:
                    self.logger.info("Returning cached node list")
                    return cached_result
            
            # Create OPC UA client
            client = OPCUAClient(connection_config)
            
            # Browse nodes
            self.logger.info(f"Starting node browse from {config['starting_node']} with depth {config['browse_depth']}")
            
            nodes = client.browse_nodes(
                start_node=config['starting_node'],
                max_depth=config['browse_depth'],
                node_class_filter=config['node_class_filter'],
                include_system=config['include_system_nodes']
            )
            
            # Apply node limit
            if config['max_nodes_limit'] > 0 and len(nodes) > config['max_nodes_limit']:
                self.logger.warning(f"Limiting output to {config['max_nodes_limit']} nodes (found {len(nodes)})")
                nodes = nodes[:config['max_nodes_limit']]
            
            # Check if any nodes found
            if not nodes:
                return self.error_handler.create_no_data_result(
                    reason="No nodes found matching browse criteria",
                    context={
                        "starting_node": config['starting_node'],
                        "node_class_filter": config['node_class_filter'],
                        "browse_depth": config['browse_depth']
                    }
                )
            
            # Get server information
            server_info = client.get_server_info()
            
            # Prepare browse parameters for output
            browse_params = {
                "starting_node": config['starting_node'],
                "max_depth": config['browse_depth'],
                "node_class_filter": config['node_class_filter'],
                "include_system_nodes": config['include_system_nodes']
            }
            
            # Calculate duration
            browse_duration = int((time.time() - start_time) * 1000)
            
            # Format output
            content = self.data_formatter.format_node_list(
                nodes=nodes,
                server_info=server_info,
                browse_params=browse_params,
                output_format=config['output_format']
            )
            
            # Update content with actual browse duration
            if config['output_format'].upper() == "JSON":
                import json
                try:
                    data = json.loads(content.decode('utf-8'))
                    data['browse_duration_ms'] = browse_duration
                    content = json.dumps(data, indent=2).encode('utf-8')
                except:
                    pass  # Keep original content if JSON parsing fails
            
            # Cache result if enabled
            if config['cache_duration'] > 0:
                self._cache_result(config, content, browse_duration)
            
            # Create success attributes
            attributes = {
                "opcua.browse.node_count": str(len(nodes)),
                "opcua.browse.starting_node": config['starting_node'],
                "opcua.browse.depth": str(config['browse_depth']),
                "opcua.browse.node_class_filter": config['node_class_filter'],
                "opcua.browse.include_system_nodes": str(config['include_system_nodes']),
                "opcua.browse.output_format": config['output_format'],
                "opcua.browse.duration_ms": str(browse_duration),
                "opcua.server.endpoint": server_info.get('endpoint_url', 'Unknown'),
                "opcua.server.name": server_info.get('server_name', 'Unknown'),
                "mime.type": self._get_mime_type(config['output_format'])
            }
            
            self.logger.info(f"Successfully browsed {len(nodes)} nodes in {browse_duration}ms")
            
            return FlowFileSourceResult(
                relationship="success",
                attributes=attributes,
                contents=content
            )
            
        except Exception as e:
            self.logger.error(f"Error browsing OPC UA nodes: {str(e)}")
            # Initialize config if error occurred before config was set
            try:
                error_context = {
                    "starting_node": config.get('starting_node', 'Unknown'),
                    "browse_depth": config.get('browse_depth', 'Unknown'),
                    "node_class_filter": config.get('node_class_filter', 'Unknown')
                }
            except NameError:
                error_context = {
                    "starting_node": "Unknown",
                    "browse_depth": "Unknown", 
                    "node_class_filter": "Unknown"
                }
            return handle_opcua_exception("GetOPCNodeList", e, error_context)
    
    def _get_configuration(self, context) -> Dict[str, Any]:
        """Extract and parse configuration properties"""
        try:
            config = {
                'starting_node': self._get_property_value(context, "Starting Node ID", "ns=0;i=85"),
                'browse_depth': int(self._get_property_value(context, "Browse Depth", "10")),
                'node_class_filter': self._get_property_value(context, "Node Class Filter", "Variable"),
                'include_system_nodes': self._get_property_value(context, "Include System Nodes", "false").lower() == "true",
                'output_format': self._get_property_value(context, "Output Format", "JSON"),
                'cache_duration': int(self._get_property_value(context, "Cache Duration", "3600")),
                'max_nodes_limit': int(self._get_property_value(context, "Max Nodes Limit", "10000"))
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
        # Validate starting node format
        starting_node = config['starting_node']
        if not starting_node:
            raise ValueError("Starting Node ID cannot be empty")
        
        # Basic node ID format validation
        if not (starting_node.startswith('ns=') or starting_node.startswith('i=') or starting_node.startswith('s=')):
            raise ValueError(f"Invalid node ID format: {starting_node}. Expected format like 'ns=0;i=85' or 'ns=2;s=TagName'")
        
        # Validate browse depth
        if config['browse_depth'] < 0:
            raise ValueError("Browse Depth cannot be negative")
        
        # Validate cache duration
        if config['cache_duration'] < 0:
            raise ValueError("Cache Duration cannot be negative")
        
        # Validate max nodes limit
        if config['max_nodes_limit'] < 0:
            raise ValueError("Max Nodes Limit cannot be negative")
    
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
    
    def _check_cache(self, config: Dict[str, Any]) -> Optional[FlowFileSourceResult]:
        """Check if cached result is available and valid"""
        # This would integrate with NiFi's state management in real implementation
        # For now, return None (no cache)
        return None
    
    def _cache_result(self, config: Dict[str, Any], content: bytes, duration_ms: int):
        """Cache the browse result for future use"""
        # This would integrate with NiFi's state management in real implementation
        pass
    
    def _get_mime_type(self, output_format: str) -> str:
        """Get MIME type based on output format"""
        format_mime_types = {
            "JSON": "application/json",
            "CSV": "text/csv", 
            "XML": "application/xml"
        }
        return format_mime_types.get(output_format.upper(), "application/octet-stream")
