add_rules("mode.debug", "mode.release")

target("patcher")
    set_kind("static")
    set_languages("c11")
    add_files("src/*.c")
    add_includedirs("src", {public = false})
    add_includedirs("include", {public = true})

target("test")
    set_kind("binary")
    add_files("test/*.c")
    add_deps("patcher")