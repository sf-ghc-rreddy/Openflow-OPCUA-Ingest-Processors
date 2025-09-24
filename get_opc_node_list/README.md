# GetOPCNodeList Processor

A custom Apache NiFi Python processor that discovers and lists available nodes (tags) from OPC UA servers.

## Overview

GetOPCNodeList browses the OPC UA server namespace to discover available nodes and their metadata. This processor is essential for understanding the structure and available data points in an OPC UA server before setting up data reading processes.

## Features

✅ **Hierarchical Browsing**: Traverses OPC UA server namespace structure  
✅ **Flexible Filtering**: Filter by node class, depth, and system nodes  
✅ **Rich Metadata**: Captures node attributes, data types, and browse paths  
✅ **Multiple Output Formats**: JSON, CSV, and XML support  
✅ **Performance Optimization**: Configurable caching and node limits  
✅ **Comprehensive Error Handling**: Detailed error reporting and recovery

## Configuration Properties

### Connection Properties
- **OPC UA Server Endpoint** (required): Server endpoint URL (e.g., `opc.tcp://localhost:4840`)
- **Security Policy**: None | Basic128Rsa15 | Basic256 | Basic256Sha256
- **Authentication Mode**: Anonymous | Username/Password | Certificate  
- **Username**: Username for authentication (optional)
- **Password**: Password for authentication (sensitive, optional)
- **Connection Timeout**: Connection timeout in seconds (default: 30)

### Browse Properties
- **Starting Node ID**: Root node to start browsing (default: `ns=0;i=85` - Objects folder)
- **Browse Depth**: Maximum depth to browse (default: 10, 0=unlimited)
- **Node Class Filter**: Variable | Object | Method | View | All (default: Variable)
- **Include System Nodes**: Include OPC UA system nodes (default: false)
- **Output Format**: JSON | CSV | XML (default: JSON)
- **Cache Duration**: Cache results duration in seconds (default: 3600)
- **Max Nodes Limit**: Maximum nodes in output (default: 10000)

## Output Relationships

- **success**: Successfully retrieved node list from OPC UA server
- **failure**: Failed to retrieve node list from OPC UA server  
- **empty**: No nodes found matching the specified criteria

## Sample Output (JSON)

```json
{
  "browse_timestamp": "2024-12-15T10:30:00Z",
  "server_info": {
    "endpoint_url": "opc.tcp://server:4840",
    "server_name": "Production OPC Server"
  },
  "browse_parameters": {
    "starting_node": "ns=0;i=85",
    "max_depth": 10,
    "node_class_filter": "Variable"
  },
  "nodes": [
    {
      "node_id": "ns=2;s=Temperature1",
      "display_name": "Temperature Sensor 1", 
      "node_class": "Variable",
      "data_type": "Double",
      "access_level": "CurrentRead",
      "browse_path": "Objects.ProcessData.Temperature1",
      "has_children": false,
      "attributes": {
        "description": "Temperature sensor reading in Celsius"
      }
    }
  ],
  "total_nodes_found": 1,
  "browse_duration_ms": 1250
}
```

## Installation

### Prerequisites
- Apache NiFi 2.0.0-M3+ with Python processor support
- Python 3.11+
- OPC UA and cryptography libraries

### Build and Install

```bash
# Build NAR file
# Clone repository
git clone <repository-url>
# Install build dependencies  
pip install hatch hatch-datavolo-nar
cd get_opc_node_list && hatch build --target nar && cd ..

# Upload NAR to Openflow Runtime Cluster or NiFi
# Navigate to Controller Settings → Local Extensions
# Upload dist/get_opc_node_list_processor-1.0.0.nar
```

## Usage Examples

### Basic Node Discovery

**Configuration:**
```
OPC UA Server Endpoint: opc.tcp://production-server:4840
Security Policy: None
Authentication Mode: Anonymous
Starting Node ID: ns=0;i=85
Browse Depth: 10
Node Class Filter: Variable
Output Format: JSON
```

### Advanced Filtering

**Configuration:**
```
Starting Node ID: ns=2;s=ProcessData
Browse Depth: 5
Node Class Filter: Variable
Include System Nodes: false
Max Nodes Limit: 1000
Cache Duration: 1800
```

### Integration Flow

```
GetOPCNodeList → EvaluateJsonPath → UpdateAttribute → GetOPCData
     ↓ success        ↓ matched         ↓ success        ↓ success
   (node list)    (extracted IDs)    (ID attributes)   (tag values)
```

## Error Handling

### Common Issues

1. **"Connection timeout"**
   - Check server endpoint URL and network connectivity
   - Verify firewall rules for OPC UA port (typically 4840)

2. **"Authentication failed"**
   - Verify username/password or certificate configuration
   - Check authentication mode settings

3. **"No nodes found"**
   - Verify starting node ID exists on server
   - Check node class filter settings
   - Increase browse depth if needed

4. **"Browse depth exceeded"** 
   - Reduce browse depth for large server namespaces
   - Use more specific starting node ID

### Error Attributes

All errors include detailed attributes:
- `opcua.error.type`: Error category
- `opcua.error.message`: Detailed error message  
- `opcua.error.user_message`: User-friendly description
- `opcua.browse.starting_node`: Starting node context
- `opcua.browse.depth`: Browse depth context

## Performance Tuning

### Large Servers
```
Browse Depth: 5 (reduce for servers with >10,000 nodes)
Max Nodes Limit: 5000 (prevent memory issues)
Cache Duration: 7200 (2-hour caching for static structures)
```

### Frequent Browsing
```
Cache Duration: 3600 (1-hour caching)
Starting Node ID: ns=2;s=SpecificArea (target specific areas)
Node Class Filter: Variable (focus on data points)
```

## Dependencies

- **opcua>=0.98.13**: Python OPC UA library
- **cryptography>=3.4.8**: Security and certificate support

## Version History

### 1.0.0
- Initial release
- Support for hierarchical browsing
- Multiple output formats
- Comprehensive error handling
- Performance optimization features

## Support

For issues and questions:
1. Check error attributes in failure FlowFiles
2. Review NiFi logs for detailed error information
3. Verify OPC UA server connectivity with external tools
4. Open GitHub issues with configuration and error details

---
