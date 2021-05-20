package common

import (
	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/DataDog/sketches-go/ddsketch/mapping"
	"github.com/DataDog/sketches-go/ddsketch/store"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConnectionsStatsJsonMarshalling(t *testing.T) {
	indexMapping, _ := mapping.NewLinearlyInterpolatedMapping(0.1)
	sketch1 := ddsketch.NewDDSketch(indexMapping, store.NewDenseStore(), store.NewDenseStore())
	sketch1.Add(0)
	connStat := ConnectionStats{
		Pid:              1,
		Type:             TCP,
		Family:           AF_INET,
		Local:            "local",
		Remote:           "remote",
		LocalPort:        4,
		RemotePort:       5,
		Direction:        INCOMING,
		State:            ACTIVE,
		NetworkNamespace: "namespace",
		SendBytes:        100,
		RecvBytes:        200,
		HttpMetrics: []HttpMetric{
			{StatusCode: 200, DDSketch: &DDSketchWrap{sketch1}},
			{StatusCode: 300, DDSketch: &DDSketchWrap{sketch1}},
		},
	}

	encoded, err := connStat.MarshalJSON()
	assert.NoError(t, err)
	decoded := &ConnectionStats{}
	err = decoded.UnmarshalJSON(encoded)
	assert.NoError(t, err)

	assertWithoutHttpMetrics(t, connStat, *decoded)
	assert.Equal(t, 1.0, decoded.HttpMetrics[0].DDSketch.DDSketch.GetCount())
	assert.Equal(t, 1.0, decoded.HttpMetrics[1].DDSketch.DDSketch.GetCount())
}

func assertWithoutHttpMetrics(t *testing.T, expected ConnectionStats, actual ConnectionStats) {
	expected.HttpMetrics = nil
	actual.HttpMetrics = nil
	assert.Equal(t, expected, actual)
}
