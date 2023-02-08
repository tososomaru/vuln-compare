import os

from vuln_compare.unify import unify_vulnerabilities

DEFAULT_DATABASES_PATH = os.path.join(os.getcwd(), "vuln-list")


def check_databases_folder(databases_path: str):
    exist = os.path.exists(databases_path)
    if not exist:
        raise NotADirectoryError()


def main():
    #TODO use cli
    databases_path = DEFAULT_DATABASES_PATH

    check_databases_folder(databases_path)

    models = unify_vulnerabilities(databases_path)


if __name__ == "__main__":
    main()
