rule FakeYaraRule {
  meta:
    description = "Placeholder YARA rule"
  strings:
    $a = "dummy"
  condition:
    $a
}
