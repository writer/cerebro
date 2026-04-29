package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("cerebro-next")
		return
	}

	fmt.Println("Cerebro rewrite in progress. The legacy implementation has been removed from the active codebase; see PLAN.md.")
}
