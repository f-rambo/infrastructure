// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.27.1
// source: api/cluster/cluster.proto

package cluster

import (
	biz "github.com/f-rambo/cloud-copilot/infrastructure/internal/biz"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_api_cluster_cluster_proto protoreflect.FileDescriptor

var file_api_cluster_cluster_proto_rawDesc = []byte{
	0x0a, 0x19, 0x61, 0x70, 0x69, 0x2f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2f, 0x63, 0x6c,
	0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x63, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x1a, 0x1a, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x62,
	0x69, 0x7a, 0x2f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x32, 0xe7, 0x03, 0x0a, 0x10, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49, 0x6e, 0x74, 0x65,
	0x72, 0x66, 0x61, 0x63, 0x65, 0x12, 0x33, 0x0a, 0x05, 0x53, 0x74, 0x61, 0x72, 0x74, 0x12, 0x14,
	0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x1a, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74,
	0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x32, 0x0a, 0x04, 0x53, 0x74,
	0x6f, 0x70, 0x12, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x1a, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x38,
	0x0a, 0x0a, 0x47, 0x65, 0x74, 0x52, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x14, 0x2e, 0x62,
	0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74,
	0x65, 0x72, 0x1a, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x42, 0x0a, 0x14, 0x4d, 0x69, 0x67, 0x72,
	0x61, 0x74, 0x65, 0x54, 0x6f, 0x42, 0x6f, 0x73, 0x74, 0x69, 0x6f, 0x6e, 0x48, 0x6f, 0x73, 0x74,
	0x12, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x43,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x1a, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x40, 0x0a, 0x12,
	0x47, 0x65, 0x74, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x49, 0x6e,
	0x66, 0x6f, 0x12, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x1a, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x35,
	0x0a, 0x07, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c, 0x12, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e,
	0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x1a,
	0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x6c,
	0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x37, 0x0a, 0x09, 0x55, 0x6e, 0x49, 0x6e, 0x73, 0x74, 0x61,
	0x6c, 0x6c, 0x12, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x1a, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x3a,
	0x0a, 0x0c, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x72, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x12, 0x14,
	0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x1a, 0x14, 0x2e, 0x62, 0x69, 0x7a, 0x2e, 0x63, 0x6c, 0x75, 0x73, 0x74,
	0x65, 0x72, 0x2e, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x42, 0x0e, 0x5a, 0x0c, 0x61, 0x70,
	0x69, 0x2f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x3b, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var file_api_cluster_cluster_proto_goTypes = []any{
	(*biz.Cluster)(nil), // 0: biz.cluster.Cluster
}
var file_api_cluster_cluster_proto_depIdxs = []int32{
	0, // 0: cluster.ClusterInterface.Start:input_type -> biz.cluster.Cluster
	0, // 1: cluster.ClusterInterface.Stop:input_type -> biz.cluster.Cluster
	0, // 2: cluster.ClusterInterface.GetRegions:input_type -> biz.cluster.Cluster
	0, // 3: cluster.ClusterInterface.MigrateToBostionHost:input_type -> biz.cluster.Cluster
	0, // 4: cluster.ClusterInterface.GetNodesSystemInfo:input_type -> biz.cluster.Cluster
	0, // 5: cluster.ClusterInterface.Install:input_type -> biz.cluster.Cluster
	0, // 6: cluster.ClusterInterface.UnInstall:input_type -> biz.cluster.Cluster
	0, // 7: cluster.ClusterInterface.HandlerNodes:input_type -> biz.cluster.Cluster
	0, // 8: cluster.ClusterInterface.Start:output_type -> biz.cluster.Cluster
	0, // 9: cluster.ClusterInterface.Stop:output_type -> biz.cluster.Cluster
	0, // 10: cluster.ClusterInterface.GetRegions:output_type -> biz.cluster.Cluster
	0, // 11: cluster.ClusterInterface.MigrateToBostionHost:output_type -> biz.cluster.Cluster
	0, // 12: cluster.ClusterInterface.GetNodesSystemInfo:output_type -> biz.cluster.Cluster
	0, // 13: cluster.ClusterInterface.Install:output_type -> biz.cluster.Cluster
	0, // 14: cluster.ClusterInterface.UnInstall:output_type -> biz.cluster.Cluster
	0, // 15: cluster.ClusterInterface.HandlerNodes:output_type -> biz.cluster.Cluster
	8, // [8:16] is the sub-list for method output_type
	0, // [0:8] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_api_cluster_cluster_proto_init() }
func file_api_cluster_cluster_proto_init() {
	if File_api_cluster_cluster_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_cluster_cluster_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_cluster_cluster_proto_goTypes,
		DependencyIndexes: file_api_cluster_cluster_proto_depIdxs,
	}.Build()
	File_api_cluster_cluster_proto = out.File
	file_api_cluster_cluster_proto_rawDesc = nil
	file_api_cluster_cluster_proto_goTypes = nil
	file_api_cluster_cluster_proto_depIdxs = nil
}
