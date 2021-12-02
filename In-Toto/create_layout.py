from securesystemslib import interface
from in_toto.models.layout import Layout
from in_toto.models.metadata import Metablock

def main():
  # Load Niels's private key to later sign the layout
  key_owner = interface.import_rsa_privatekey_from_file("owner/owner")
  # Fetch and load aimee's and noud's public keys
  # to specify that they are authorized to perform certain step in the layout
  key_pub = interface.import_rsa_publickey_from_file("owner/owner.pub")
  key_build = interface.import_rsa_publickey_from_file("build/build.pub")

  layout = Layout.read({
      "_type": "layout",
      "keys": {
          key_pub["keyid"]: key_pub,
          key_build["keyid"]: key_build,
      },
      "steps": [{
          "name": "commit",
          "expected_materials": [],
          "expected_products": [["CREATE", "*"], ["DISALLOW", "*"]],
          "pubkeys": [key_pub["keyid"]],
          "expected_command": [
              "git",
              "commit",
              "-S"
          ],
          "threshold": 1,
        },{
          "name": "publish",
          "expected_materials": [
            ["MATCH", "*", "WITH", "PRODUCTS", "FROM",
             "commit"],
          ],
          "expected_products": [["CREATE", "pub/*"], ["DISALLOW", "*"]],
          "pubkeys": [key_build["keyid"]],
          "expected_command": [
              "dotnet",
              "publish",
              "-o",
              "pub"
          ],
          "threshold": 1,
        },{
          "name": "sast",
          "expected_products": [["CREATE", "pipeline.json"], ["DISALLOW", "*"]],
          "pubkeys": [key_build["keyid"]],
          "threshold": 1,
        }],
      "inspect": [{
          "name": "zip",
          "run": [
              "unzip",
              "pub.zip",
          ]
        }],
  })

  metadata = Metablock(signed=layout)

  # Sign and dump layout to "root.layout"
  metadata.sign(key_owner)
  metadata.dump("root.layout")

if __name__ == '__main__':
  main()
