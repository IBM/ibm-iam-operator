package utils

import (
	"math/rand"
	"time"

	regen "github.com/zach-klippenstein/goregen"
)

// GenerateRandomString generates a random string based upon a string that is a valid regex pattern.
func GenerateRandomString(rule string) string {

	generator, _ := regen.NewGenerator(rule, &regen.GeneratorArgs{
		RngSource:               rand.NewSource(time.Now().UnixNano()),
		MaxUnboundedRepeatCount: 1})
	randomString := generator.Generate()
	return randomString
}
