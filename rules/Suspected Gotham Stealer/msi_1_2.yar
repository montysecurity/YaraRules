/*
   YARA Rule Set
   Author: @_montysecurity
   Date: 2023-10-05
*/

/* Rule Set ----------------------------------------------------------------- */

rule potential_gotham_stealer {
   meta:
      description = " - file potential_gotham_stealer.msi"
      author = "@_montysecurity"
      date = "2023-10-05"
      hash1 = "05d60e098aa8e62108cd641125fcf2105688e484454bb7c0ccbcf8c5cefc1070"
   strings:
      $x1 = "gothammanufcaturer" ascii
   condition:
      $x1
}