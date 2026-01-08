from typing import Any, Optional

__all__ = (
    'yaml_load',
    'yaml_dump',
    'HAS_YAML',
)

try:
    import ruamel.yaml.representer

    from ruamel.yaml import YAML
    from io import StringIO

    class YamlRepresenter(ruamel.yaml.representer.RoundTripRepresenter):
        __slots__ = ()

        def represent_str(self, data: Any) -> Any:
            if '\n' in data:
                return self.represent_scalar('tag:yaml.org,2002:str', data, style='|')
            return self.represent_scalar('tag:yaml.org,2002:str', data)

    YamlRepresenter.add_representer(str, YamlRepresenter.represent_str)

    def yaml_load(stream) -> Any:
        yaml = YAML(typ='safe', pure=True)
        return yaml.load(stream)

    def yaml_dump(data: Any, /, indent: Optional[int] = None) -> str:
        yaml = YAML(typ='safe', pure=True)
        yaml.Representer = YamlRepresenter
        yaml.default_flow_style = False
        yaml.allow_unicode = True

        if indent is not None:
            yaml.indent = indent

        stream = StringIO()
        yaml.dump(data, stream)

        return stream.getvalue()

    HAS_YAML = True
except ImportError:
    try:
        from yaml import ( # type: ignore
            safe_load as yaml_load,
            safe_dump as yaml_dump, # type: ignore
        )

        HAS_YAML = True
    except ImportError:
        HAS_YAML = False

        import json

        def yaml_load(stream) -> Any:
            raise NotImplementedError('Reading YAML files requires the `PyYAML` package.')

        def yaml_dump(data: Any, /, indent: Optional[int] = None) -> str:
            return json.dumps(data, indent=indent)
