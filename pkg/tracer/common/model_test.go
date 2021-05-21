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
		Metrics: []ConnectionMetric{
			{
				Name: "http_response_time_seconds",
				Tags: map[TagName]string{
					HTTPStatusCode: "200",
				},
				Value: ConnectionMetricValue{
					&Histogram{sketch1},
				},
			},
		},
	}

	encoded, err := connStat.MarshalJSON()
	assert.NoError(t, err)
	decoded := &ConnectionStats{}
	err = decoded.UnmarshalJSON(encoded)
	assert.NoError(t, err)

	assertWithoutMetrics(t, connStat, *decoded)
	assert.Equal(t, 1.0, decoded.Metrics[0].Value.Histogram.DDSketch.GetCount())
}

func assertWithoutMetrics(t *testing.T, expected ConnectionStats, actual ConnectionStats) {
	expected.Metrics = nil
	actual.Metrics = nil
	assert.Equal(t, expected, actual)
}
