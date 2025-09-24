# Openflow-OPCUA-Ingest-Processors
A suite of custom Python processors for Apache NiFi and Snowflake Openflow that enables seamless integration with OPC UA servers. Built using the Datavolo/Apache NiFi Python framework.

## 🏗️ **Project Structure**

This project provides **two processors** for OPC UA connectivity in Apache NiFi and Snowflake Openflow, each deployable separately:

### 📋 **GetOPCNodeList** (Independent Processor)  
- **Project**: [`get_opc_node_list/`](get_opc_node_list/)
- **NAR File**: `get_opc_node_list_processor-1.0.0.nar` (13KB)
- **Purpose**: Discovers and lists available OPC UA nodes/tags
- **Features**: Hierarchical browsing, filtering, multiple output formats
- **Documentation**: [GetOPCNodeList README](get_opc_node_list/README.md)

### 📊 **GetOPCData** (Independent Processor)
- **Project**: [`get_opc_data/`](get_opc_data/)  
- **NAR File**: `get_opc_data_processor-1.0.0.nar` (15KB)
- **Purpose**: Reads current/historical values from specified nodes
- **Features**: Quality filtering, timestamp selection, batch processing
- **Documentation**: [GetOPCData README](get_opc_data/README.md)

## ✨ **Key Benefits**

✅ **Complete OPC UA Integration**
- Tag discovery and metadata extraction
- Current and historical data reading
- Configurable timestamp selection  
- Optional null value exclusion
- Quality information and error handling

✅ **Production-Ready Features**
- Comprehensive error handling and recovery
- Performance optimization with caching
- Extensive configuration options
- Multiple output formats (JSON, CSV, XML)

✅ **Security & Authentication**
- Anonymous, Username/Password, Certificate authentication
- All OPC UA security policies supported
- SSL/TLS encryption and certificate management

## 🔧 **Configuration Overview**

### Connection Properties (Both Processors)
Each processor includes independent OPC UA connection configuration:

```
OPC UA Server Endpoint: opc.tcp://server:4840 (required)
Security Policy: None | Basic128Rsa15 | Basic256 | Basic256Sha256  
Authentication Mode: Anonymous | Username/Password | Certificate
Username: username (optional)
Password: ******** (sensitive, optional)
Connection Timeout: 30 seconds
```

### GetOPCNodeList Specific Properties
```
Starting Node ID: ns=0;i=85 (Objects folder)
Browse Depth: 10 (0 = unlimited)  
Node Class Filter: Variable | Object | Method | View | All
Include System Nodes: false
Output Format: JSON | CSV | XML
Cache Duration: 3600 seconds
Max Nodes Limit: 10000
```

### GetOPCData Specific Properties  
```
Node IDs: ns=2;s=Temperature1,ns=2;s=Pressure1 (required)
Read Mode: Current | Historical
Timestamp Selection: Server | Source | Both
Exclude Null Values: true
Include Quality Info: true  
Output Format: JSON | CSV | XML
Batch Size: 100 nodes
Max Age: 0 seconds (0 = no limit)
```

## Usage Examples

### 1. Basic Node Discovery

**Flow**: `GetOPCNodeList` → `EvaluateJsonPath` → `PutSnowflake`

```json
{
  "browse_timestamp": "2024-12-15T10:30:00Z",
  "server_info": {
    "endpoint_url": "opc.tcp://server:4840",
    "server_name": "Production OPC Server"
  },
  "nodes": [
    {
      "node_id": "ns=2;s=Temperature1",
      "display_name": "Temperature Sensor 1",
      "node_class": "Variable",
      "data_type": "Double",
      "browse_path": "Objects.ProcessData.Temperature1"
    }
  ],
  "total_nodes_found": 150
}
```

### 2. Data Reading with Quality Info

**Flow**: `GetOPCData` → `RouteOnAttribute` → `[PutSnowflake | AlertManager]`

```json
{
  "read_timestamp": "2024-12-15T10:30:15Z",
  "data_points": [
    {
      "node_id": "ns=2;s=Temperature1",
      "display_name": "Temperature Sensor 1",
      "value": 23.7,
      "data_type": "Double",
      "server_timestamp": "2024-12-15T10:30:14.123Z",
      "quality": {
        "code": "Good",
        "description": "The value is good"
      },
      "status": "Success"
    }
  ],
  "summary": {
    "total_requested": 1,
    "successful_reads": 1,
    "failed_reads": 0
  }
}
```

### 3. CSV Output for Analysis

**Flow**: `GetOPCData` (CSV mode) → `ConvertRecord` → `PutSnowflakeTableRecord`

```csv
node_id,display_name,value,data_type,server_timestamp,quality_code,status
ns=2;s=Temperature1,Temperature Sensor 1,23.7,Double,2024-12-15T10:30:14.123Z,Good,Success
ns=2;s=Pressure1,Pressure Sensor 1,1.25,Double,2024-12-15T10:30:14.125Z,Good,Success
```

