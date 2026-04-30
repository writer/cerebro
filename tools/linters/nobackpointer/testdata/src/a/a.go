package a

type App struct{}

type Server struct{}

type Client struct{}

type AppAlias = *App

type ServerList []*Server

type Good struct {
	client *Client
}

type GoodByValue struct {
	app App
}

type BadApp struct {
	app *App // want `back-pointer to \*App`
}

type BadServer struct {
	server *Server // want `back-pointer to \*Server`
}

type BadAlias struct {
	app AppAlias // want `back-pointer to \*App`
}

type BadSlice struct {
	servers ServerList // want `back-pointer to \*Server`
}

type BadMap struct {
	apps map[string]*App // want `back-pointer to \*App`
}

//cerebro:lint:allow nobackpointer legacy shim https://example.com/issue/7
type Allowed struct {
	app *App
}
