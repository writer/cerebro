package a

type App struct{}

type Server struct{}

type Client struct{}

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

//cerebro:lint:allow nobackpointer legacy shim https://example.com/issue/7
type Allowed struct {
	app *App
}
