// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package common

import (
	json "encoding/json"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjsonC80ae7adDecodeGithubComStackVistaTcptracerBpfPkgTracerCommon(in *jlexer.Lexer, out *Metric) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "labels":
			if in.IsNull() {
				in.Skip()
			} else {
				in.Delim('{')
				out.Labels = make(map[string]string)
				for !in.IsDelim('}') {
					key := string(in.String())
					in.WantColon()
					var v1 string
					v1 = string(in.String())
					(out.Labels)[key] = v1
					in.WantComma()
				}
				in.Delim('}')
			}
		case "ddsketch":
			if in.IsNull() {
				in.Skip()
				out.DDSketch = nil
			} else {
				out.DDSketch = in.Bytes()
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGithubComStackVistaTcptracerBpfPkgTracerCommon(out *jwriter.Writer, in Metric) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"labels\":"
		out.RawString(prefix[1:])
		if in.Labels == nil && (out.Flags&jwriter.NilMapAsEmpty) == 0 {
			out.RawString(`null`)
		} else {
			out.RawByte('{')
			v3First := true
			for v3Name, v3Value := range in.Labels {
				if v3First {
					v3First = false
				} else {
					out.RawByte(',')
				}
				out.String(string(v3Name))
				out.RawByte(':')
				out.String(string(v3Value))
			}
			out.RawByte('}')
		}
	}
	{
		const prefix string = ",\"ddsketch\":"
		out.RawString(prefix)
		out.Base64Bytes(in.DDSketch)
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v Metric) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonC80ae7adEncodeGithubComStackVistaTcptracerBpfPkgTracerCommon(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v Metric) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGithubComStackVistaTcptracerBpfPkgTracerCommon(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *Metric) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGithubComStackVistaTcptracerBpfPkgTracerCommon(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *Metric) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGithubComStackVistaTcptracerBpfPkgTracerCommon(l, v)
}
func easyjsonC80ae7adDecodeGithubComStackVistaTcptracerBpfPkgTracerCommon1(in *jlexer.Lexer, out *Connections) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "connections":
			if in.IsNull() {
				in.Skip()
				out.Conns = nil
			} else {
				in.Delim('[')
				if out.Conns == nil {
					if !in.IsDelim(']') {
						out.Conns = make([]ConnectionStats, 0, 0)
					} else {
						out.Conns = []ConnectionStats{}
					}
				} else {
					out.Conns = (out.Conns)[:0]
				}
				for !in.IsDelim(']') {
					var v6 ConnectionStats
					if data := in.Raw(); in.Ok() {
						in.AddError((v6).UnmarshalJSON(data))
					}
					out.Conns = append(out.Conns, v6)
					in.WantComma()
				}
				in.Delim(']')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGithubComStackVistaTcptracerBpfPkgTracerCommon1(out *jwriter.Writer, in Connections) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"connections\":"
		out.RawString(prefix[1:])
		if in.Conns == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v7, v8 := range in.Conns {
				if v7 > 0 {
					out.RawByte(',')
				}
				out.Raw((v8).MarshalJSON())
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v Connections) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonC80ae7adEncodeGithubComStackVistaTcptracerBpfPkgTracerCommon1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v Connections) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGithubComStackVistaTcptracerBpfPkgTracerCommon1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *Connections) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGithubComStackVistaTcptracerBpfPkgTracerCommon1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *Connections) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGithubComStackVistaTcptracerBpfPkgTracerCommon1(l, v)
}
func easyjsonC80ae7adDecodeGithubComStackVistaTcptracerBpfPkgTracerCommon2(in *jlexer.Lexer, out *ConnectionStats) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "pid":
			out.Pid = uint32(in.Uint32())
		case "type":
			out.Type = ConnectionType(in.Uint8())
		case "family":
			out.Family = ConnectionFamily(in.Uint8())
		case "app_proto":
			out.ApplicationProtocol = string(in.String())
		case "local":
			out.Local = string(in.String())
		case "remote":
			out.Remote = string(in.String())
		case "lport":
			out.LocalPort = uint16(in.Uint16())
		case "rport":
			out.RemotePort = uint16(in.Uint16())
		case "direction":
			out.Direction = Direction(in.Uint8())
		case "state":
			out.State = State(in.Uint8())
		case "network_namespace":
			out.NetworkNamespace = string(in.String())
		case "send_bytes":
			out.SendBytes = uint64(in.Uint64())
		case "recv_bytes":
			out.RecvBytes = uint64(in.Uint64())
		case "metrics":
			if in.IsNull() {
				in.Skip()
				out.Metrics = nil
			} else {
				in.Delim('[')
				if out.Metrics == nil {
					if !in.IsDelim(']') {
						out.Metrics = make([]Metric, 0, 2)
					} else {
						out.Metrics = []Metric{}
					}
				} else {
					out.Metrics = (out.Metrics)[:0]
				}
				for !in.IsDelim(']') {
					var v9 Metric
					if data := in.Raw(); in.Ok() {
						in.AddError((v9).UnmarshalJSON(data))
					}
					out.Metrics = append(out.Metrics, v9)
					in.WantComma()
				}
				in.Delim(']')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonC80ae7adEncodeGithubComStackVistaTcptracerBpfPkgTracerCommon2(out *jwriter.Writer, in ConnectionStats) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"pid\":"
		out.RawString(prefix[1:])
		out.Uint32(uint32(in.Pid))
	}
	{
		const prefix string = ",\"type\":"
		out.RawString(prefix)
		out.Uint8(uint8(in.Type))
	}
	{
		const prefix string = ",\"family\":"
		out.RawString(prefix)
		out.Uint8(uint8(in.Family))
	}
	{
		const prefix string = ",\"app_proto\":"
		out.RawString(prefix)
		out.String(string(in.ApplicationProtocol))
	}
	{
		const prefix string = ",\"local\":"
		out.RawString(prefix)
		out.String(string(in.Local))
	}
	{
		const prefix string = ",\"remote\":"
		out.RawString(prefix)
		out.String(string(in.Remote))
	}
	{
		const prefix string = ",\"lport\":"
		out.RawString(prefix)
		out.Uint16(uint16(in.LocalPort))
	}
	{
		const prefix string = ",\"rport\":"
		out.RawString(prefix)
		out.Uint16(uint16(in.RemotePort))
	}
	{
		const prefix string = ",\"direction\":"
		out.RawString(prefix)
		out.Uint8(uint8(in.Direction))
	}
	{
		const prefix string = ",\"state\":"
		out.RawString(prefix)
		out.Uint8(uint8(in.State))
	}
	{
		const prefix string = ",\"network_namespace\":"
		out.RawString(prefix)
		out.String(string(in.NetworkNamespace))
	}
	{
		const prefix string = ",\"send_bytes\":"
		out.RawString(prefix)
		out.Uint64(uint64(in.SendBytes))
	}
	{
		const prefix string = ",\"recv_bytes\":"
		out.RawString(prefix)
		out.Uint64(uint64(in.RecvBytes))
	}
	{
		const prefix string = ",\"metrics\":"
		out.RawString(prefix)
		if in.Metrics == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v10, v11 := range in.Metrics {
				if v10 > 0 {
					out.RawByte(',')
				}
				out.Raw((v11).MarshalJSON())
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v ConnectionStats) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonC80ae7adEncodeGithubComStackVistaTcptracerBpfPkgTracerCommon2(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v ConnectionStats) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGithubComStackVistaTcptracerBpfPkgTracerCommon2(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *ConnectionStats) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGithubComStackVistaTcptracerBpfPkgTracerCommon2(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *ConnectionStats) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGithubComStackVistaTcptracerBpfPkgTracerCommon2(l, v)
}
