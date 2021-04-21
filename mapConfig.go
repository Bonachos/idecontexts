package main

// MapConfig contains a MapStore Map configuration
type MapConfig struct {
	Map             `json:"map"`
	CatalogServices CatalogServices `json:"catalogServices,omitempty"`
	Version         int             `json:"version"`
	EmailAddress    string          `json:"emailAddress"`
}

// Center contains the center position of a map
type Center struct {
	X   float64 `json:"x,omitempty"`
	Y   float64 `json:"y,omitempty"`
	Crs string  `json:"crs,omitempty"`
}

type View struct {
	Resolutions []float64 `json:"resolutions,omitempty"`
}

type MapOptions struct {
	View View `json:"view,omitempty"`
}

type Options struct {
	URL                 string   `json:"url"`
	TypeName            string   `json:"typeName"`
	QueriableAttributes []string `json:"queriableAttributes"`
	SortBy              string   `json:"sortBy"`
	MaxFeatures         int      `json:"maxFeatures"`
	SrsName             string   `json:"srsName"`
}

type TextSerchConfigServices struct {
	Type        string  `json:"type"`
	Name        string  `json:"name"`
	DisplayName string  `json:"displayName"`
	SubTitle    string  `json:"subTitle"`
	Priority    int     `json:"priority"`
	Options     Options `json:"options,omitempty"`
}

type TextSerchConfig struct {
	Services []TextSerchConfigServices `json:"services,omitempty"`
	Override bool                      `json:"override,omitempty"`
}

type Search struct {
	URL  string `json:"url,omitempty"`
	Type string `json:"type,omitempty"`
}

// Layer contains the information of a layer
type Layer struct {
	Type       string `json:"type"`
	URL        string `json:"url,omitempty"`
	Visibility bool   `json:"visibility"`
	Tiled      bool   `json:"tiled"`
	TileSize   int    `json:"tileSize"`
	// Opacity    string `json:"opacity"`
	Title              string        `json:"title"`
	Provider           string        `json:"provider,omitempty"`
	Name               string        `json:"name,omitempty"`
	Source             string        `json:"source,omitempty"`
	Group              string        `json:"group"`
	Format             string        `json:"format,omitempty"`
	Args               []interface{} `json:"args,omitempty"`
	Dimensions         []interface{} `json:"dimensions,omitempty"`
	Fixed              bool          `json:"fixed,omitempty"`
	HandleClickOnLayer bool          `json:"handleClickOnLayer,omitempty"`
	Hidden             bool          `json:"hidden,omitempty"`
	HideLoading        bool          `json:"hideLoading,omitempty"`
	Search             Search        `json:"search,omitempty"`
	SingleTile         bool          `json:"singleTile,omitempty"`
	Style              interface{}   `json:"style,omitempty"`
	Features           []Feature     `json:"features"`
	UseForElevation    bool          `json:"useForElevation,omitempty"`
	CatalogURL         string        `json:"catalogURL,omitempty"`
}

type Feature struct {
	Type       string          `json:"type"`
	Geometry   FeatureGeometry `json:"geometry"`
	Properties TextSerchConfig `json:"properties"`
	Features   []Feature       `json:"features"`
	ID         int64           `json:"id"`
	Style      interface{}     `json:"style,omitempty"`
}

type FeatureGeometry struct {
	Type        string        `json:"type"`
	Coordinates []interface{} `json:"coordinates"`
}

type MapGroups struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Expanded bool   `json:"expanded"`
}

// Map contains a Map configuration
type Map struct {
	Projection      string `json:"projection"`
	Units           string `json:"units"`
	Center          `json:"center,omitempty"`
	MapOptions      MapOptions      `json:"mapOptions"`
	Zoom            int             `json:"zoom,omitempty"`
	MinZoom         int             `json:"minZoom,omitempty"`
	MaxZoom         int             `json:"maxZoom,omitempty"`
	TextSerchConfig TextSerchConfig `json:"text_serch_config,omitempty"`
	MaxExtent       []float64       `json:"maxExtent"`
	Layers          []Layer         `json:"layers"`
	Groups          []MapGroups     `json:"groups,omitempty"`
	PrintMapHeader  string          `json:"mapHeader,omitempty"`
	PrintMapNorth   string          `json:"mapNorth,omitempty"`
}

type GsWms struct {
	URL      string `json:"url,omitempty"`
	Type     string `json:"type,omitempty"`
	Title    string `json:"title,omitempty"`
	Autoload bool   `json:"autoload,omitempty"`
}

type CatalogServicesServices struct {
	GsCsw GsWms `json:"gs_csw,omitempty"`
	GsWms GsWms `json:"gs_wms,omitempty"`
}

type CatalogServices struct {
	Services CatalogServicesServices `json:"services,omitempty"`
}
