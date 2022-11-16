{#- Since `-bxor` triggers some anti malware scanners, use this trick -#}
function {{symbol_name("xor")}} {
    return [Byte]((-bnot($args[0] -band $args[1])) -band (-bnot((-bnot $args[0]) -band (-bnot $args[1]))))
};

{#- Text book implementation of RC4 -#}

function {{symbol_name("Decrypt-RC4")}} {
    $s = New-Object Byte[] 256;
    $k = New-Object Byte[] 256;

    for ($i = 0; $i -lt 256; $i++)
    {
        $s[$i] = [Byte]$i;
        $k[$i] = $args[1][$i % $args[1].Length];
    };

    $j = 0;
    for ($i = 0; $i -lt 256; $i++)
    {
        $j = ($j + $s[$i] + $k[$i]) % 256;
        $m = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $m;
    };

    $i = $j = 0;
    for ($x = 0; $x -lt $args[0].Length; $x++)
    {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        $m = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $m;
        [int]$t = ($s[$i] + $s[$j]) % 256;
        $args[0][$x] = {{symbol_name("xor")}} $args[0][$x] $s[$t];
    };

    $args[0]
};
