package dj

import (
	"encoding/json"
	"testing"
)

func TestSearchPagingObjects(t *testing.T) {
	var result SearchResult
	err := json.Unmarshal([]byte(`{"tracks":{"items":[{"id":"mock","name":"Roi","uri":"spotify:track:mock","artists":[{"name":"VIDEOCLUB"}],"external_urls":{"spotify":"https://open.spotify.com/track/mock"}}],"limit":5,"offset":0,"total":1,"next":null,"previous":null}}`), &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.Tracks == nil || len(result.Tracks.Items) != 1 || result.Tracks.Items[0].Artists[0].Name != "VIDEOCLUB" || result.Tracks.Total != 1 {
		t.Fatal("search page fields lost")
	}
}
