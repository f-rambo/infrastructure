// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.27.1
// source: api/log/log.proto

package log

import (
	common "github.com/f-rambo/cloud-copilot/infrastructure/api/common"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_api_log_log_proto protoreflect.FileDescriptor

var file_api_log_log_proto_rawDesc = []byte{
	0x0a, 0x11, 0x61, 0x70, 0x69, 0x2f, 0x6c, 0x6f, 0x67, 0x2f, 0x6c, 0x6f, 0x67, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x16, 0x69, 0x6e, 0x66, 0x72, 0x61, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74,
	0x75, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x6c, 0x6f, 0x67, 0x1a, 0x1b, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70,
	0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x61, 0x70, 0x69, 0x2f, 0x63, 0x6f,
	0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x5f, 0x72, 0x65, 0x61, 0x73, 0x6f,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x15, 0x61, 0x70, 0x69, 0x2f, 0x6c, 0x6f, 0x67,
	0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x32, 0x93,
	0x01, 0x0a, 0x0c, 0x4c, 0x6f, 0x67, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x12,
	0x2b, 0x0a, 0x04, 0x50, 0x69, 0x6e, 0x67, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a,
	0x0b, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x4d, 0x73, 0x67, 0x12, 0x56, 0x0a, 0x07,
	0x47, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x73, 0x12, 0x22, 0x2e, 0x69, 0x6e, 0x66, 0x72, 0x61, 0x73,
	0x74, 0x72, 0x75, 0x63, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x6c, 0x6f, 0x67,
	0x2e, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x23, 0x2e, 0x69, 0x6e,
	0x66, 0x72, 0x61, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x6c, 0x6f, 0x67, 0x2e, 0x4c, 0x6f, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x28, 0x01, 0x30, 0x01, 0x42, 0x0a, 0x5a, 0x08, 0x61, 0x70, 0x69, 0x2f, 0x6c, 0x6f, 0x67, 0x3b,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_api_log_log_proto_goTypes = []any{
	(*emptypb.Empty)(nil), // 0: google.protobuf.Empty
	(*LogRequest)(nil),    // 1: infrastructure.api.log.LogRequest
	(*common.Msg)(nil),    // 2: common.Msg
	(*LogResponse)(nil),   // 3: infrastructure.api.log.LogResponse
}
var file_api_log_log_proto_depIdxs = []int32{
	0, // 0: infrastructure.api.log.LogInterface.Ping:input_type -> google.protobuf.Empty
	1, // 1: infrastructure.api.log.LogInterface.GetLogs:input_type -> infrastructure.api.log.LogRequest
	2, // 2: infrastructure.api.log.LogInterface.Ping:output_type -> common.Msg
	3, // 3: infrastructure.api.log.LogInterface.GetLogs:output_type -> infrastructure.api.log.LogResponse
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_api_log_log_proto_init() }
func file_api_log_log_proto_init() {
	if File_api_log_log_proto != nil {
		return
	}
	file_api_log_message_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_log_log_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_log_log_proto_goTypes,
		DependencyIndexes: file_api_log_log_proto_depIdxs,
	}.Build()
	File_api_log_log_proto = out.File
	file_api_log_log_proto_rawDesc = nil
	file_api_log_log_proto_goTypes = nil
	file_api_log_log_proto_depIdxs = nil
}
