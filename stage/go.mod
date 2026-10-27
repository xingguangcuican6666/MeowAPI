// stage/ holds files recovered from the archived new-api fork. They import
// github.com/QuantumNous/new-api/... and are reference material only, not part
// of the MeowAPI build. This go.mod exists so the Go tool prunes the directory
// from the root module's ./... patterns. Do not build it; port from it.
module github.com/xingguangcuican6666/meowapi/stage

go 1.27.3
