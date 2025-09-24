# GetOPCData Processor

A custom Apache NiFi Python processor that reads current values from specified OPC UA nodes/tags with comprehensive quality filtering and timestamp management.

## Overview

GetOPCData reads current or historical values from specified OPC UA nodes, providing rich metadata including quality information, timestamps, and error handling. This processor is designed for reliable industrial data ingestion with configurable quality filtering.

## Features

✅ **Current Value Reading**: Read real-time values from OPC UA nodes  
✅ **Quality Filtering**: Optional exclusion of null/bad quality values  
✅ **Timestamp Selection**: Choose server, source, or both timestamps  
✅ **Multiple Output Formats**: JSON, CSV, and XML support  
✅ **Batch Processing**: Configurable batch sizes for large node lists  
✅ **Partial Success Handling**: Continue processing when some nodes fail  
✅ **Rich Metadata**: Includes data types, quality codes, and error details

## Configuration Properties

### Connection Properties
- **OPC UA Server Endpoint** (required): Server endpoint URL (e.g., `opc.tcp://localhost:4840`)
- **Security Policy**: None | Basic128Rsa15 | Basic256 | Basic256Sha256
- **Authentication Mode**: Anonymous | Username/Password | Certificate
- **Username**: Username for authentication (optional)
- **Password**: Password for authentication (sensitive, optional)
- **Connection Timeout**: Connection timeout in seconds (default: 30)

### Data Reading Properties
- **Node IDs** (required): Comma-separated list of node IDs (e.g., `ns=2;s=Temperature1,ns=2;s=Pressure1`)
- **Read Mode**: Current | Historical (default: Current)
- **Timestamp Selection**: Server | Source | Both (default: Server)
- **Exclude Null Values**: Exclude null/bad quality values (default: true)
- **Include Quality Info**: Include OPC UA quality information (default: true)
- **Output Format**: JSON | CSV | XML (default: JSON)
- **Max Age**: Maximum age of cached values in seconds (default: 0)
- **Batch Size**: Maximum nodes per batch (default: 100)

### Historical Properties (when Read Mode = Historical)
- **Start Time**: Start time for historical data (ISO format or relative like -1h)
- **End Time**: End time for historical data (ISO format or relative like -30m)
- **Processing Interval**: Interval for data aggregation in milliseconds (default: 1000)
- **Max Historical Points**: Maximum historical points per node (default: 1000)

## Output Relationships

- **success**: Successfully read data from OPC UA server
- **failure**: Failed to read data from OPC UA server
- **partial_success**: Some nodes read successfully, others failed  
- **no_data**: No valid data found (all null or bad quality)

## Sample Output (JSON)

```json
{
  "read_timestamp": "2024-12-15T10:30:15Z",
  "server_info": {
    "endpoint_url": "opc.tcp://server:4840",
    "server_name": "Production OPC Server"
  },
  "read_parameters": {
    "read_mode": "Current",
    "timestamp_selection": "Server", 
    "exclude_null_values": true,
    "include_quality_info": true
  },
  "data_points": [
    {
      "node_id": "ns=2;s=Temperature1",
      "display_name": "Temperature Sensor 1",
      "value": 23.7,
      "data_type": "Double",
      "server_timestamp": "2024-12-15T10:30:14.123Z",
      "source_timestamp": "2024-12-15T10:30:14.120Z", 
      "quality": {
        "code": "Good",
        "description": "The value is good",
        "numeric_code": 0
      },
      "status": "Success"
    }
  ],
  "summary": {
    "total_requested": 1,
    "successful_reads": 1,
    "failed_reads": 0,
    "null_values_excluded": 0
  },
  "read_duration_ms": 245
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
cd get_opc_data && hatch build --target nar && cd ..


# Upload NAR to Openflow Runtime Cluster or NiFi
# Navigate to Controller Settings → Local Extensions  
# Upload dist/get_opc_data_processor-1.0.0.nar
```

## Usage Examples

### Basic Data Reading

**Configuration:**
```
OPC UA Server Endpoint: opc.tcp://production-server:4840
Security Policy: None
Authentication Mode: Anonymous
Node IDs: ns=2;s=Temperature1,ns=2;s=Pressure1,ns=2;s=Flow1
Timestamp Selection: Server
Exclude Null Values: true
Output Format: JSON
```

### Quality-Filtered Reading

**Configuration:**
```
Node IDs: ns=2;s=Sensor1,ns=2;s=Sensor2,ns=2;s=Sensor3
Exclude Null Values: true
Include Quality Info: true
Max Age: 5
Batch Size: 50
```

### CSV Output for Analytics

**Configuration:**
```
Node IDs: ns=2;s=Temperature1,ns=2;s=Pressure1
Output Format: CSV
Timestamp Selection: Both
Include Quality Info: false
```

### Integration Flows

#### Real-time Monitoring
```
GetOPCData (scheduled) → RouteOnAttribute → PutSnowflake
     ↓ success              ↓ quality=Good    ↓ normal
   (current values)      (route by quality)  (store data)
```

#### Data Pipeline
```
GetOPCNodeList → EvaluateJsonPath → UpdateAttribute → GetOPCData → PutSnowflake
     ↓ success        ↓ matched         ↓ success        ↓ success      ↓ success
   (discover nodes) (extract IDs)    (set node list)   (read values)  (store data)
```

## Error Handling

### Common Issues

1. **"Node not found"**
   - Verify node IDs exist on server
   - Use GetOPCNodeList to discover valid node IDs
   - Check node ID format: `ns=2;s=TagName` or `ns=0;i=2256`

2. **"Connection timeout"**
   - Check server endpoint URL and network connectivity
   - Verify firewall rules and server availability

3. **"Authentication failed"**
   - Verify username/password or certificate configuration
   - Check authentication mode matches server requirements

4. **"Bad quality values"**
   - Check if Exclude Null Values is enabled
   - Verify sensors/devices connected to OPC UA server
   - Review quality codes in output

### Relationship Routing

**success**: All nodes read successfully  
**partial_success**: Some nodes succeeded, some failed  
**failure**: Complete failure (connection, authentication, etc.)  
**no_data**: All values filtered out due to quality or null checks

### Error Attributes

Detailed error information in FlowFile attributes:
- `opcua.error.type`: Error category 
- `opcua.error.message`: Technical error details
- `opcua.error.user_message`: User-friendly description
- `opcua.read.failed_nodes`: List of failed node IDs
- `opcua.read.successful`: Count of successful reads

## Performance Tuning

### Large Node Lists
```
Batch Size: 50 (reduce for slower servers)
Max Age: 10 (use cached values up to 10 seconds)
Node IDs: Group related nodes together
```

### High-Frequency Reading
```
Exclude Null Values: true (reduce data volume)
Include Quality Info: false (smaller FlowFiles)
Output Format: CSV (more compact than JSON)
Max Age: 5 (balance freshness vs performance)
```

### Quality Monitoring
```
Exclude Null Values: false (see all data)
Include Quality Info: true (full quality details)
Timestamp Selection: Both (complete timing info)
```

## Quality Codes

Common OPC UA quality codes:
- **Good**: Value is good and reliable
- **Bad_NotConnected**: Device not connected
- **Bad_DeviceFailure**: Device hardware failure
- **Bad_SensorFailure**: Sensor malfunction
- **Bad_ConfigurationError**: Configuration issue
- **Uncertain**: Value may be inaccurate
- **Good_LocalOverride**: Value manually overridden

## Node ID Formats

### Supported Formats
```
ns=2;s=Temperature1          # String identifier
ns=0;i=2256                  # Numeric identifier  
ns=3;s=Area1.Temperature     # Hierarchical string
ns=2;s=Device_01.Sensor_02   # Device-specific
```

### Discovery Workflow
1. Use GetOPCNodeList to discover available nodes
2. Extract node IDs from discovery results
3. Configure GetOPCData with discovered node IDs

## Dependencies

- **opcua>=0.98.13**: Python OPC UA library
- **cryptography>=3.4.8**: Security and certificate support

