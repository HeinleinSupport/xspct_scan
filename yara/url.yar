rule SpamRedirect_loja_acscientifica {
    meta:
        description = "Spam tracker/affiliate redirect via loja.acscientifica.com.br"
        reference   = "report 5 — FS-11-26-FP_000033118_010088-26-WF.html"
        tlp         = "white"

    strings:
        $url = "loja.acscientifica.com.br" ascii wide nocase

    condition:
        $url
}
