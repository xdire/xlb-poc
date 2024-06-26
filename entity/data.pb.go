// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v4.25.3
// source: data.proto

package entity

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Strategy int32

const (
	Strategy_RoundRobin Strategy = 0
	Strategy_LeastConn  Strategy = 1
)

// Enum value maps for Strategy.
var (
	Strategy_name = map[int32]string{
		0: "RoundRobin",
		1: "LeastConn",
	}
	Strategy_value = map[string]int32{
		"RoundRobin": 0,
		"LeastConn":  1,
	}
)

func (x Strategy) Enum() *Strategy {
	p := new(Strategy)
	*p = x
	return p
}

func (x Strategy) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Strategy) Descriptor() protoreflect.EnumDescriptor {
	return file_data_proto_enumTypes[0].Descriptor()
}

func (Strategy) Type() protoreflect.EnumType {
	return &file_data_proto_enumTypes[0]
}

func (x Strategy) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Strategy.Descriptor instead.
func (Strategy) EnumDescriptor() ([]byte, []int) {
	return file_data_proto_rawDescGZIP(), []int{0}
}

type Client struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uuid      string                 `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	Key       string                 `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	Name      string                 `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,10,opt,name=createdAt,proto3" json:"createdAt,omitempty"`
}

func (x *Client) Reset() {
	*x = Client{}
	if protoimpl.UnsafeEnabled {
		mi := &file_data_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Client) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Client) ProtoMessage() {}

func (x *Client) ProtoReflect() protoreflect.Message {
	mi := &file_data_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Client.ProtoReflect.Descriptor instead.
func (*Client) Descriptor() ([]byte, []int) {
	return file_data_proto_rawDescGZIP(), []int{0}
}

func (x *Client) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *Client) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Client) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Client) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

type FrontendTLSData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key         string `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	Certificate string `protobuf:"bytes,3,opt,name=certificate,proto3" json:"certificate,omitempty"`
}

func (x *FrontendTLSData) Reset() {
	*x = FrontendTLSData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_data_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FrontendTLSData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FrontendTLSData) ProtoMessage() {}

func (x *FrontendTLSData) ProtoReflect() protoreflect.Message {
	mi := &file_data_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FrontendTLSData.ProtoReflect.Descriptor instead.
func (*FrontendTLSData) Descriptor() ([]byte, []int) {
	return file_data_proto_rawDescGZIP(), []int{1}
}

func (x *FrontendTLSData) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *FrontendTLSData) GetCertificate() string {
	if x != nil {
		return x.Certificate
	}
	return ""
}

type Frontend struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uuid            string           `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	Active          bool             `protobuf:"varint,2,opt,name=active,proto3" json:"active,omitempty"`
	Strategy        Strategy         `protobuf:"varint,3,opt,name=strategy,proto3,enum=github.com.xdire.xlb.v1.Strategy" json:"strategy,omitempty"`
	RouteTimeoutSec int32            `protobuf:"varint,4,opt,name=routeTimeoutSec,proto3" json:"routeTimeoutSec,omitempty"`
	ClientId        string           `protobuf:"bytes,5,opt,name=clientId,proto3" json:"clientId,omitempty"`
	AccessKey       string           `protobuf:"bytes,6,opt,name=accessKey,proto3" json:"accessKey,omitempty"`
	Routes          []*FrontendRoute `protobuf:"bytes,8,rep,name=routes,proto3" json:"routes,omitempty"`
}

func (x *Frontend) Reset() {
	*x = Frontend{}
	if protoimpl.UnsafeEnabled {
		mi := &file_data_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Frontend) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Frontend) ProtoMessage() {}

func (x *Frontend) ProtoReflect() protoreflect.Message {
	mi := &file_data_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Frontend.ProtoReflect.Descriptor instead.
func (*Frontend) Descriptor() ([]byte, []int) {
	return file_data_proto_rawDescGZIP(), []int{2}
}

func (x *Frontend) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *Frontend) GetActive() bool {
	if x != nil {
		return x.Active
	}
	return false
}

func (x *Frontend) GetStrategy() Strategy {
	if x != nil {
		return x.Strategy
	}
	return Strategy_RoundRobin
}

func (x *Frontend) GetRouteTimeoutSec() int32 {
	if x != nil {
		return x.RouteTimeoutSec
	}
	return 0
}

func (x *Frontend) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *Frontend) GetAccessKey() string {
	if x != nil {
		return x.AccessKey
	}
	return ""
}

func (x *Frontend) GetRoutes() []*FrontendRoute {
	if x != nil {
		return x.Routes
	}
	return nil
}

type FrontendRoute struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Dest     string `protobuf:"bytes,1,opt,name=dest,proto3" json:"dest,omitempty"`
	Capacity int32  `protobuf:"varint,3,opt,name=capacity,proto3" json:"capacity,omitempty"`
}

func (x *FrontendRoute) Reset() {
	*x = FrontendRoute{}
	if protoimpl.UnsafeEnabled {
		mi := &file_data_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FrontendRoute) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FrontendRoute) ProtoMessage() {}

func (x *FrontendRoute) ProtoReflect() protoreflect.Message {
	mi := &file_data_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FrontendRoute.ProtoReflect.Descriptor instead.
func (*FrontendRoute) Descriptor() ([]byte, []int) {
	return file_data_proto_rawDescGZIP(), []int{3}
}

func (x *FrontendRoute) GetDest() string {
	if x != nil {
		return x.Dest
	}
	return ""
}

func (x *FrontendRoute) GetCapacity() int32 {
	if x != nil {
		return x.Capacity
	}
	return 0
}

type Backend struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uuid     string   `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	Frontend string   `protobuf:"bytes,2,opt,name=frontend,proto3" json:"frontend,omitempty"`
	Strategy Strategy `protobuf:"varint,3,opt,name=strategy,proto3,enum=github.com.xdire.xlb.v1.Strategy" json:"strategy,omitempty"`
}

func (x *Backend) Reset() {
	*x = Backend{}
	if protoimpl.UnsafeEnabled {
		mi := &file_data_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Backend) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Backend) ProtoMessage() {}

func (x *Backend) ProtoReflect() protoreflect.Message {
	mi := &file_data_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Backend.ProtoReflect.Descriptor instead.
func (*Backend) Descriptor() ([]byte, []int) {
	return file_data_proto_rawDescGZIP(), []int{4}
}

func (x *Backend) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *Backend) GetFrontend() string {
	if x != nil {
		return x.Frontend
	}
	return ""
}

func (x *Backend) GetStrategy() Strategy {
	if x != nil {
		return x.Strategy
	}
	return Strategy_RoundRobin
}

type BackendRoute struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Route         string `protobuf:"bytes,1,opt,name=route,proto3" json:"route,omitempty"`
	Sessions      int32  `protobuf:"varint,2,opt,name=sessions,proto3" json:"sessions,omitempty"`
	TotalSessions int64  `protobuf:"varint,5,opt,name=totalSessions,proto3" json:"totalSessions,omitempty"`
}

func (x *BackendRoute) Reset() {
	*x = BackendRoute{}
	if protoimpl.UnsafeEnabled {
		mi := &file_data_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BackendRoute) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BackendRoute) ProtoMessage() {}

func (x *BackendRoute) ProtoReflect() protoreflect.Message {
	mi := &file_data_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BackendRoute.ProtoReflect.Descriptor instead.
func (*BackendRoute) Descriptor() ([]byte, []int) {
	return file_data_proto_rawDescGZIP(), []int{5}
}

func (x *BackendRoute) GetRoute() string {
	if x != nil {
		return x.Route
	}
	return ""
}

func (x *BackendRoute) GetSessions() int32 {
	if x != nil {
		return x.Sessions
	}
	return 0
}

func (x *BackendRoute) GetTotalSessions() int64 {
	if x != nil {
		return x.TotalSessions
	}
	return 0
}

var File_data_proto protoreflect.FileDescriptor

var file_data_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x17, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x78, 0x64, 0x69, 0x72, 0x65, 0x2e, 0x78,
	0x6c, 0x62, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x7c, 0x0a, 0x06, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x12, 0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x75, 0x75, 0x69, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x38, 0x0a, 0x09, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x64, 0x41, 0x74, 0x22, 0x45, 0x0a, 0x0f, 0x46, 0x72, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x64,
	0x54, 0x4c, 0x53, 0x44, 0x61, 0x74, 0x61, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x65, 0x72,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x22, 0x99, 0x02, 0x0a, 0x08,
	0x46, 0x72, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x75, 0x69, 0x64, 0x12, 0x16, 0x0a, 0x06,
	0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x61, 0x63,
	0x74, 0x69, 0x76, 0x65, 0x12, 0x3d, 0x0a, 0x08, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x21, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2e, 0x78, 0x64, 0x69, 0x72, 0x65, 0x2e, 0x78, 0x6c, 0x62, 0x2e, 0x76, 0x31,
	0x2e, 0x53, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x52, 0x08, 0x73, 0x74, 0x72, 0x61, 0x74,
	0x65, 0x67, 0x79, 0x12, 0x28, 0x0a, 0x0f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65,
	0x6f, 0x75, 0x74, 0x53, 0x65, 0x63, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0f, 0x72, 0x6f,
	0x75, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x53, 0x65, 0x63, 0x12, 0x1a, 0x0a,
	0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x4b, 0x65, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x4b, 0x65, 0x79, 0x12, 0x3e, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65,
	0x73, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x78, 0x64, 0x69, 0x72, 0x65, 0x2e, 0x78, 0x6c, 0x62, 0x2e, 0x76,
	0x31, 0x2e, 0x46, 0x72, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x64, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52,
	0x06, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x22, 0x3f, 0x0a, 0x0d, 0x46, 0x72, 0x6f, 0x6e, 0x74,
	0x65, 0x6e, 0x64, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x65, 0x73, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x64, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08,
	0x63, 0x61, 0x70, 0x61, 0x63, 0x69, 0x74, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08,
	0x63, 0x61, 0x70, 0x61, 0x63, 0x69, 0x74, 0x79, 0x22, 0x78, 0x0a, 0x07, 0x42, 0x61, 0x63, 0x6b,
	0x65, 0x6e, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x75, 0x75, 0x69, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x66, 0x72, 0x6f, 0x6e, 0x74,
	0x65, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x72, 0x6f, 0x6e, 0x74,
	0x65, 0x6e, 0x64, 0x12, 0x3d, 0x0a, 0x08, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x21, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2e, 0x78, 0x64, 0x69, 0x72, 0x65, 0x2e, 0x78, 0x6c, 0x62, 0x2e, 0x76, 0x31, 0x2e,
	0x53, 0x74, 0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x52, 0x08, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65,
	0x67, 0x79, 0x22, 0x66, 0x0a, 0x0c, 0x42, 0x61, 0x63, 0x6b, 0x65, 0x6e, 0x64, 0x52, 0x6f, 0x75,
	0x74, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x73, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x73, 0x12, 0x24, 0x0a, 0x0d, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x53, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x74, 0x6f, 0x74,
	0x61, 0x6c, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2a, 0x29, 0x0a, 0x08, 0x53, 0x74,
	0x72, 0x61, 0x74, 0x65, 0x67, 0x79, 0x12, 0x0e, 0x0a, 0x0a, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x52,
	0x6f, 0x62, 0x69, 0x6e, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x4c, 0x65, 0x61, 0x73, 0x74, 0x43,
	0x6f, 0x6e, 0x6e, 0x10, 0x01, 0x42, 0x19, 0x5a, 0x17, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x78, 0x64, 0x69, 0x72, 0x65, 0x2f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_data_proto_rawDescOnce sync.Once
	file_data_proto_rawDescData = file_data_proto_rawDesc
)

func file_data_proto_rawDescGZIP() []byte {
	file_data_proto_rawDescOnce.Do(func() {
		file_data_proto_rawDescData = protoimpl.X.CompressGZIP(file_data_proto_rawDescData)
	})
	return file_data_proto_rawDescData
}

var file_data_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_data_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_data_proto_goTypes = []interface{}{
	(Strategy)(0),                 // 0: github.com.xdire.xlb.v1.Strategy
	(*Client)(nil),                // 1: github.com.xdire.xlb.v1.Client
	(*FrontendTLSData)(nil),       // 2: github.com.xdire.xlb.v1.FrontendTLSData
	(*Frontend)(nil),              // 3: github.com.xdire.xlb.v1.Frontend
	(*FrontendRoute)(nil),         // 4: github.com.xdire.xlb.v1.FrontendRoute
	(*Backend)(nil),               // 5: github.com.xdire.xlb.v1.Backend
	(*BackendRoute)(nil),          // 6: github.com.xdire.xlb.v1.BackendRoute
	(*timestamppb.Timestamp)(nil), // 7: google.protobuf.Timestamp
}
var file_data_proto_depIdxs = []int32{
	7, // 0: github.com.xdire.xlb.v1.Client.createdAt:type_name -> google.protobuf.Timestamp
	0, // 1: github.com.xdire.xlb.v1.Frontend.strategy:type_name -> github.com.xdire.xlb.v1.Strategy
	4, // 2: github.com.xdire.xlb.v1.Frontend.routes:type_name -> github.com.xdire.xlb.v1.FrontendRoute
	0, // 3: github.com.xdire.xlb.v1.Backend.strategy:type_name -> github.com.xdire.xlb.v1.Strategy
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_data_proto_init() }
func file_data_proto_init() {
	if File_data_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_data_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Client); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_data_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FrontendTLSData); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_data_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Frontend); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_data_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FrontendRoute); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_data_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Backend); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_data_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BackendRoute); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_data_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_data_proto_goTypes,
		DependencyIndexes: file_data_proto_depIdxs,
		EnumInfos:         file_data_proto_enumTypes,
		MessageInfos:      file_data_proto_msgTypes,
	}.Build()
	File_data_proto = out.File
	file_data_proto_rawDesc = nil
	file_data_proto_goTypes = nil
	file_data_proto_depIdxs = nil
}
