cwlVersion: v1.2
class: CommandLineTool
id: hello
baseCommand: echo
inputs:
  message:
    type: string
    default: Hello world
    inputBinding:
      position: 1
outputs: []
$namespaces:
  s: https://schema.org/
s:name: Hello
s:description: A minimal template-generation example.
s:dateCreated: '2026-09-18'
s:license: https://spdx.org/licenses/Apache-2.0
s:softwareVersion: '0.1.0'
s:softwareHelp:
  s:name: User guide
  s:url: https://example.org/hello
s:publisher:
  s:name: Example Organization
s:author:
  s:givenName: Example
  s:familyName: Author
  s:email: author@example.org
  s:affiliation:
    s:name: Example Organization
