package api

import (
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/utils"
)

func deckList(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	return c.JSON(http.StatusOK, myDice.DeckList)
}

func deckReload(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	dice.DeckReload(myDice)
	return c.JSON(http.StatusOK, true)
}

func deckUpload(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	//-----------
	// Read file
	//-----------

	// Source
	file, err := c.FormFile("file")
	if err != nil {
		return err
	}
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer func(src multipart.File) {
		_ = src.Close()
	}(src)

	file.Filename = strings.ReplaceAll(file.Filename, "/", "_")
	file.Filename = strings.ReplaceAll(file.Filename, "\\", "_")
	if err = utils.AtomicWriteReader(filepath.Join("./data/decks", file.Filename), src, 0o644); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, nil)
}

func deckEnable(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	v := struct {
		Filename string `json:"filename"`
		Enable   bool   `json:"enable"`
	}{}
	err := c.Bind(&v)

	if err == nil {
		for _, deck := range myDice.DeckList {
			if deck.Filename == v.Filename {
				deck.Enable = v.Enable
				myDice.MarkModified()
				break
			}
		}
	}

	return c.JSON(http.StatusOK, myDice.Config.BanList)
}

func deckDelete(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	v := struct {
		Filename string `json:"filename"`
	}{}
	err := c.Bind(&v)

	if err == nil && v.Filename != "" {
		for _, deck := range myDice.DeckList {
			if deck.Filename == v.Filename {
				dice.DeckDelete(myDice, deck)
				myDice.MarkModified()
				break
			}
		}
	}

	return c.JSON(http.StatusOK, nil)
}

func deckCheckUpdate(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}
	v := struct {
		Filename string `json:"filename"`
	}{}
	err := c.Bind(&v)

	if err == nil && v.Filename != "" {
		for _, deck := range myDice.DeckList {
			if deck.Filename == v.Filename {
				oldDeck, newDeck, tempFileName, err := myDice.DeckCheckUpdate(deck)
				if err != nil {
					return Error(&c, err.Error(), Response{})
				}
				return Success(&c, Response{
					"old":          oldDeck,
					"new":          newDeck,
					"format":       deck.FileFormat,
					"filename":     deck.Filename,
					"tempFileName": tempFileName,
				})
			}
		}
	}
	return Success(&c, Response{})
}

func deckUpdate(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}
	v := struct {
		Filename     string `json:"filename"`
		TempFileName string `json:"tempFileName"`
	}{}
	err := c.Bind(&v)

	if err == nil && v.Filename != "" {
		for _, deck := range myDice.DeckList {
			if deck.Filename == v.Filename {
				err := myDice.DeckUpdate(deck, v.TempFileName)
				if err != nil {
					return Error(&c, err.Error(), Response{})
				}
				myDice.MarkModified()
				break
			}
		}
	}
	return Success(&c, Response{})
}
