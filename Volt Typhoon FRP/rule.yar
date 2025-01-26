/*
   YARA Rule Set
   Author: @_montysecurity
   Date: 2025-01-26
*/

/* Rule Set ----------------------------------------------------------------- */

rule volt_typhoon_frp_config {
   meta:
      description = "Strings related to frp config"
      author = "@_montysecurity"
      reference = "https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/"
      date = "2025-01-26"
      hash1 = "baeffeb5fdef2f42a752c65c2d2a52e84fb57efc906d981f89dd518c314e231c"
   strings:
      $s1 = "token = 851e14f2414876f1158a45faa5ffe4b6" ascii
      $s2 = "24.29.81.183" ascii
      $x1 = "[common]" ascii
      $x2 = "[plugin_socks5]" ascii
   condition:
      all of ($x*) and any of ($s*)
}