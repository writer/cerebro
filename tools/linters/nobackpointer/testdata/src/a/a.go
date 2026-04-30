package a

import "external"

type App struct{}

type Server struct{}

type Client struct{}

type Good struct {
	client *Client
}

type GoodExternal struct {
	app    *external.App
	server *external.Server
}

type GoodByValue struct {
	app App
}

type AppRef *App

type ServerRef *Server

type AppList []*App

type ServerMap map[string]*Server

type ExternalAppRef *external.App

type BadApp struct {
	app *App // want `back-pointer to \*App`
}

type BadServer struct {
	server *Server // want `back-pointer to \*Server`
}

type BadAppAlias struct {
	app AppRef // want `back-pointer to \*App`
}

type BadServerAlias struct {
	server ServerRef // want `back-pointer to \*Server`
}

type BadAppList struct {
	apps []*App // want `back-pointer to \*App`
}

type BadServerMap struct {
	servers map[string]*Server // want `back-pointer to \*Server`
}

type BadAppListAlias struct {
	apps AppList // want `back-pointer to \*App`
}

type BadServerMapAlias struct {
	servers ServerMap // want `back-pointer to \*Server`
}

type GoodExternalAlias struct {
	app ExternalAppRef
}

//cerebro:lint:allow nobackpointer legacy shim https://example.com/issue/7
type Allowed struct {
	app *App
}
