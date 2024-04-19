# SecureBox

Gestor de contraseñas local con copias de seguridad en la nube.

Implementado en el Proyecto 1 de Ciberseguridad por Bhavuk Sikka y Samuel de Lucas Maroto.


## Quickstart

```sh
$ git clone https://github.com/Bubbasm/securebox.git && cd securebox
$ pip install -r requirements.txt
$ cp securebox.json $HOME/.local/share/securebox.json
$ python src/securebox.py -h
usage: securebox.py [--tui | --gui]
                    (--create | --view CONTAINER_ID | --edit CONTAINER_ID | --delete CONTAINER_ID | --verify-integrity | --upload | --download | --change-password | --regenerate-keys | --set-credentials FILE | --sign-out | --print-paths | -v | -h)
                    [--name NAME] [--text TEXT]

SecureBox v0.1: a local password manager written in python.

Application mode:
  Run the TUI/GUI versions instead of the default CLI. If these are provided any other arguments will be ignored.

  --tui                 run the application in text mode
  --gui                 run the application in graphical mode

CLI Options:
  --create              create new container (see --name/--text options below)
  --view CONTAINER_ID   view container contents (full vault integrity not verified)
  --edit CONTAINER_ID   edit container (see --name/--text options below)
  --delete CONTAINER_ID
                        delete container
  --verify-integrity    verify the integrity of the vault
  --upload              upload backup to the cloud (see --set-credentials)
  --download            download backup from the cloud (see --set-credentials)
  --change-password     change the master password of the vault
  --regenerate-keys     regenerate all derived keys
  --set-credentials FILE
                        set Google Cloud credentials (OAuth 2.0) for backups
  --sign-out            remove the token associated to your personal Google account (not the Google Cloud credentials)
  --print-paths         print the paths of the save file and the configuration file
  -v, --version         print version and exit
  -h, --help            print help message and exit

Options for --create, --edit:
  --name NAME           Name for the container
  --text TEXT           Text for the container
```
