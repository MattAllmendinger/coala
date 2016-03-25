from contextlib import contextmanager
from functools import partialmethod
import inspect
import re
import shutil
from subprocess import check_call, CalledProcessError, DEVNULL
from types import MappingProxyType

from coalib.bears.LocalBear import LocalBear
from coalib.misc.ContextManagers import make_temp
from coalib.misc.Decorators import assert_right_type, enforce_signature
from coalib.misc.Shell import run_shell_command
from coalib.results.Diff import Diff
from coalib.results.Result import Result
from coalib.results.RESULT_SEVERITY import RESULT_SEVERITY
from coalib.settings.FunctionMetadata import FunctionMetadata


# TODO Doctests: Adjust: plain executable does not work!

# TODO Afterwork improvements:
# TODO - Allow to leave out mandatory arguments if unused? Affects
# TODO   create_arguments, generate_config and process_output
# TODO - Use metaclass that overrides __repr__
# TODO - static property for get_executable()
# TODO - prerequisite_check_command: Remove and let the user override it
# TODO   himself + provide helper utilities (advanced custom command check,
# TODO   derivations for specific stuff (java module check etc.)
# TODO - Enum for output_format?
# TODO - csv output parser + integrate into bears that use csv
# TODO - concept for a generic json output parser
# TODO - bears: Use regex-format placeholders (maybe use validators?)
# TODO - Move out result-from-diff generator, but without removing the `self`
# TODO   passing in the result, this isn't possible. next-gen design would help
# TODO - enable multiline mode? or provide an extra field for match flags?
# TODO - Issue for bears to advertise "path" type more for run-parameters!
# TODO - More intelligent metadata-merge that is not so merge-order-sensitive


@enforce_signature
def Linter(executable: str,
           use_stdin: bool=False,
           output_stream: str="stdout",
           config_suffix: str="",
           prerequisite_check_command: tuple=(),
           output_format: (str, None)=None,
           **options):
    """
    Decorator that creates a ``LocalBear`` that is able to process results from
    an external linter tool.

    The main functionality is achieved through the ``create_arguments()``
    function that constructs the command-line-arguments that get parsed to your
    executable.

    >>> @Linter("xlint", output_format="regex", output_regex="...")
    ... class XLintBear:
    ...     @staticmethod
    ...     def create_arguments(filename, file, config_file):
    ...         return "--lint", filename

    Requiring settings is possible like in ``Bear.run()`` with supplying
    additional keyword arguments (and if needed with defaults).

    >>> @Linter("xlint", output_format="regex", output_regex="...")
    ... class XLintBear:
    ...     @staticmethod
    ...     def create_arguments(filename,
    ...                          file,
    ...                          config_file,
    ...                          lintmode: str,
    ...                          enable_aggressive_lints: bool=False):
    ...         arguments = ("--lint", filename, "--mode=" + lintmode)
    ...         if enable_aggressive_lints:
    ...             arguments += ("--aggressive",)
    ...         return arguments

    Sometimes your tool requires an actual file that contains configuration.
    ``Linter`` allows you to just define the contents the configuration shall
    contain via ``generate_config()`` and handles everything else for you.

    >>> @Linter("xlint", output_format="regex", output_regex="...")
    ... class XLintBear:
    ...     @staticmethod
    ...     def generate_config(filename,
    ...                         file,
    ...                         lintmode,
    ...                         enable_aggressive_lints):
    ...         modestring = ("aggressive"
    ...                       if enable_aggressive_lints else
    ...                       "non-aggressive")
    ...         contents = ("<xlint>",
    ...                     "    <mode>" + lintmode + "</mode>",
    ...                     "    <aggressive>" + modestring + "</aggressive>",
    ...                     "</xlint>")
    ...         return "\\n".join(contents)
    ...
    ...     @staticmethod
    ...     def create_arguments(filename,
    ...                          file,
    ...                          config_file):
    ...         return "--lint", filename, "--config", config_file

    As you can see you don't need to copy additional keyword-arguments you
    introduced from ``create_arguments()`` to ``generate_config()`` and
    vice-versa. ``Linter`` takes care of forwarding the right arguments to the
    right place, so you are able to avoid signature duplication.

    If you override ``process_output``, you have the same feature like above
    (auto-forwarding of the right arguments defined in your function
    signature).

    Documentation:
    Bear description shall be provided at class level.
    If you document your additional parameters inside ``create_arguments``,
    ``generate_config`` and ``process_output``, beware that conflicting
    documentation between them may be overridden. Document duplicated
    parameters inside ``create_arguments`` first, then in ``generate_config``
    and after that inside ``process_output``.

    For the tutorial see:
    http://coala.readthedocs.org/en/latest/Users/Tutorials/Linter_Bears.html

    :param executable:
        The linter tool.
    :param use_stdin:
        Whether the input file is sent via stdin instead of passing it over the
        command-line-interface.
    :param output_stream:
        The output streams to grab from the executable. Possible values are
        ``stdout``, ``stderr`` or ``stdout+stderr`` (or ``stderr+stdout``).
        Providing an unknown value raises a ``ValueError``.

        Note when overriding ``process_output``: Providing a single output
        stream puts the according string attained from the stream into
        parameter ``output``, providing more than one output stream inputs
        a tuple in the same order like specified for this argument.
    :param config_suffix:
        The suffix-string to append to the filename of the configuration file
        created when ``generate_config`` is supplied. Useful if your executable
        expects getting a specific file-type with specific file-ending for the
        configuration file.
    :param prerequisite_check_command:
        A custom command to check for when ``check_prerequisites`` gets
        invoked (via ``subprocess.check_call()``). Must be an ``Iterable``.
    :param prerequisite_check_fail_message:
        A custom command to check for when ``check_prerequisites`` gets
        invoked. Must be provided only together with
        ``prerequisite_check_command``.
    :param output_format:
        The output format of the underlying executable. Valid values are

        - ``None``: Define your own format by overriding ``process_output``.
          Overriding ``process_output`` is then mandatory, not specifying it
          raises a ``ValueError``.
        - ``'regex'``: Parse output using a regex. See parameter
          ``output_regex``.
        - ``'corrected'``: The output is the corrected of the given file. Diffs
          are then generated to supply patches for results.

        Passing something else raises a ``ValueError``.
    :param output_regex:
        The regex expression as a string that is used to parse the output
        generated by the underlying executable. It should use as many of the
        following named groups (via ``(?P<name>...)``) to provide a good
        result:

        - line - The line where the issue starts.
        - column - The column where the issue starts.
        - end_line - The line where the issue ends.
        - end_column - The column where the issue ends.
        - severity - The severity of the issue.
        - message - The message of the result.
        - origin - The origin of the issue.

        The groups ``line``, ``column``, ``end_line`` and ``end_column`` don't
        have to match numbers only, they can also match nothing, the generated
        ``Result`` is filled automatically with ``None`` then for the
        appropriate properties.

        Needs to be provided if ``output_format`` is ``'regex'``.
    :param severity_map:
        A dict used to map a severity string (captured from the
        ``output_regex`` with the named group ``severity``) to an actual
        ``coalib.results.RESULT_SEVERITY`` for a result.

        - ``RESULT_SEVERITY.MAJOR``
          Mapped by ``error``, ``Error`` or ``ERROR``.
        - ``RESULT_SEVERITY.NORMAL``
          Mapped by ``warning``, ``Warning``, ``WARNING``, ``warn``, ``Warn``
          or ``WARN``.
        - ``RESULT_SEVERITY.MINOR``
          Mapped by ``info``, ``Info`` or ``INFO``.

        A ``ValueError`` is raised when the named group ``severity`` is not
        used inside ``output_regex`` and this parameter is given.
    :param diff_severity:
        The severity to use for all results if ``output_format`` is
        ``'corrected'``. By default this value is
        ``coalib.results.RESULT_SEVERITY.NORMAL``. The given value needs to be
        defined inside ``coalib.results.RESULT_SEVERITY``.
    :param diff_message:
        The message-string to use for all results if ``output_format`` is
        ``'corrected'``. By default this value is ``"Inconsistency found."``.
    :raises ValueError:
        Raised when invalid options are supplied.
    :raises TypeError:
        Raised when incompatible types are supplied.
        See parameter documentations for allowed types.
    :return:
        A ``LocalBear`` derivation that lints code using an external tool.
    """
    options["executable"] = executable
    options["output_format"] = output_format
    options["use_stdin"] = use_stdin
    options["output_stream"] = output_stream
    options["config_suffix"] = config_suffix
    options["prerequisite_check_command"] = prerequisite_check_command

    allowed_options = {"executable",
                       "output_format",
                       "use_stdin",
                       "output_stream",
                       "config_suffix",
                       "prerequisite_check_command"}

    output_stream_to_index_map = {"stdout": 0, "stderr": 1}
    try:
        stream_indices = []
        for stream in options["output_stream"].split("+"):
            stream_indices.append(output_stream_to_index_map[stream])
        options["output_stream"] = tuple(stream_indices)
    except KeyError:
        raise ValueError("Invalid output stream: " + repr(stream))

    if options["output_format"] == "corrected":
        if "diff_severity" in options:
            if options["diff_severity"] not in RESULT_SEVERITY.reverse:
                raise TypeError("Invalid value for `diff_severity`: " +
                                repr(options["diff_severity"]))

        if "diff_message" in options:
            assert_right_type(options["diff_message"], str, "diff_message")

        allowed_options |= {"diff_severity", "diff_message"}
    elif options["output_format"] == "regex":
        if "output_regex" not in options:
            raise ValueError("No `output_regex` specified.")

        options["output_regex"] = re.compile(options["output_regex"])

        # Don't setup severity_map if one is provided by user or if it's not
        # used inside the output_regex. If one is manually provided but not
        # used in the output_regex, throw an exception.
        if "severity_map" in options:
            if "severity" not in options["output_regex"].groupindex:
                raise ValueError("Provided `severity_map` but named group "
                                 "`severity` is not used in `output_regex`.")
            assert_right_type(options["severity_map"], dict, "severity_map")

            for key, value in options["severity_map"].items():
                try:
                    assert_right_type(key, str, "<severity_map dict-key>")
                except TypeError:
                    raise TypeError("The key " + repr(key) + " inside given "
                                    "severity-map is no string.")

                try:
                    assert_right_type(value, int, "<severity_map dict-value>")
                except TypeError:
                    raise TypeError(
                        "The value {} for key {} inside given severity-map is "
                        "no valid severity value.".format(repr(value),
                                                          repr(key)))

                if value not in RESULT_SEVERITY.reverse:
                    raise TypeError(
                        "Invalid severity value {} for key {} inside given "
                        "severity-map.".format(repr(value), repr(key)))

            # Copy the severity map, so users can't change it afterwards.
            options["severity_map"] = dict(options["severity_map"])

        allowed_options |= {"output_regex", "severity_map"}
    elif options["output_format"] is not None:
        raise ValueError("Invalid `output_format` specified.")

    if options["prerequisite_check_command"]:
        if "prerequisite_check_fail_message" in options:
            assert_right_type(options["prerequisite_check_fail_message"],
                              str,
                              "prerequisite_check_fail_message")
        else:
            options["prerequisite_check_fail_message"] = (
                "Prerequisite check failed.")

        allowed_options.add("prerequisite_check_fail_message")

    # Check for illegal superfluous options.
    superfluous_options = options.keys() - allowed_options
    if superfluous_options:
        raise ValueError(
            "Invalid keyword arguments provided: " +
            ", ".join(repr(s) for s in sorted(superfluous_options)))

    def create_linter(klass):
        class LinterBase(LocalBear):

            @staticmethod
            def generate_config(filename, file):
                """
                Generates the content of a config-file the linter-tool might
                need.

                The contents generated from this function are written to a
                temporary file and the path is provided inside
                ``create_arguments()``.

                By default no configuration is generated.

                You can provide additional keyword arguments and defaults.
                These will be interpreted as required settings that need to be
                provided through a coafile-section.

                :param filename:
                    The name of the file currently processed.
                :param file:
                    The contents of the file currently processed.
                :return:
                    The config-file-contents as a string or ``None``.
                """
                return None

            @staticmethod
            def create_arguments(filename, file, config_file):
                """
                Creates the arguments for the linter.

                You can provide additional keyword arguments and defaults.
                These will be interpreted as required settings that need to be
                provided through a coafile-section.

                :param filename:
                    The name of the file the linter-tool shall process.
                :param file:
                    The contents of the file.
                :param config_file:
                    The path of the config-file if used. ``None`` if unused.
                :return:
                    A sequence of arguments to feed the linter-tool with.
                """
                raise NotImplementedError

            @staticmethod
            def get_executable():
                """
                Returns the executable of this class.

                :return:
                    The executable name.
                """
                return options["executable"]

            @classmethod
            def check_prerequisites(cls):
                """
                Checks whether the linter-tool the bear uses is operational.

                :return:
                    True if available, otherwise a string containing more info.
                """
                if shutil.which(cls.get_executable()) is None:
                    return repr(cls.get_executable()) + " is not installed."
                else:
                    if options["prerequisite_check_command"]:
                        try:
                            check_call(options["prerequisite_check_command"],
                                       stdout=DEVNULL,
                                       stderr=DEVNULL)
                            return True
                        except (OSError, CalledProcessError):
                            return options["prerequisite_check_fail_message"]
                    return True

            @classmethod
            def _get_create_arguments_metadata(cls):
                return FunctionMetadata.from_function(
                    cls.create_arguments,
                    omit={"filename", "file", "config_file"})

            @classmethod
            def _get_generate_config_metadata(cls):
                return FunctionMetadata.from_function(
                    cls.generate_config,
                    omit={"filename", "file"})

            @classmethod
            def _get_process_output_metadata(cls):
                return FunctionMetadata.from_function(
                    cls.process_output,
                    omit={"self", "output", "filename", "file"})

            @classmethod
            def get_non_optional_settings(cls):
                return cls.get_metadata().non_optional_params

            @classmethod
            def get_metadata(cls):
                merged_metadata = FunctionMetadata.merge(
                    cls._get_process_output_metadata(),
                    cls._get_generate_config_metadata(),
                    cls._get_create_arguments_metadata())
                merged_metadata.desc = inspect.getdoc(cls)
                return merged_metadata

            @classmethod
            def _execute_command(cls, args, stdin=None):
                """
                Executes the underlying tool with the given arguments.

                :param args:
                    The argument sequence to pass to the executable.
                :param stdin:
                    Input to send to the opened process as stdin.
                :return:
                    A tuple with ``(stdout, stderr)``.
                """
                return run_shell_command(
                    (cls.get_executable(),) + tuple(args),
                    stdin=stdin)

            def _convert_output_regex_match_to_result(self,
                                                      match,
                                                      filename,
                                                      severity_map):
                """
                Converts the matched named-groups of ``output_regex`` to an
                actual ``Result``.

                :param match:
                    The regex match object.
                :param filename:
                    The name of the file this match belongs to.
                :param severity_map:
                    The dict to use to map the severity-match to an actual
                    ``RESULT_SEVERITY``.
                """
                # Pre process the groups
                groups = match.groupdict()

                try:
                    groups["severity"] = severity_map[groups["severity"]]
                except KeyError:
                    self.warn(
                        "No correspondence for " + repr(groups["severity"]) +
                        " found in given severity map. Assuming "
                        "`RESULT_SEVERITY.NORMAL`.")
                    groups["severity"] = RESULT_SEVERITY.NORMAL

                for variable in ("line", "column", "end_line", "end_column"):
                    groups[variable] = (None
                                        if groups.get(variable, "") == "" else
                                        int(groups[variable]))

                if "origin" in groups:
                    groups["origin"] = "{} ({})".format(
                        str(klass.__name__),
                        str(groups["origin"]))

                # Construct the result.
                return Result.from_values(
                    origin=groups.get("origin", self),
                    message=groups.get("message", ""),
                    file=filename,
                    severity=int(groups.get("severity",
                                            RESULT_SEVERITY.NORMAL)),
                    line=groups["line"],
                    column=groups["column"],
                    end_line=groups["end_line"],
                    end_column=groups["end_column"])

            def process_output_corrected(self,
                                         output,
                                         filename,
                                         file,
                                         diff_severity=RESULT_SEVERITY.NORMAL,
                                         diff_message="Inconsistency found."):
                """
                Processes the executable's output as a corrected file.

                :param output:
                    The output of the program. This can be either a single
                    string or a sequence of strings.
                :param filename:
                    The filename of the file currently being corrected.
                :param file:
                    The contents of the file currently being corrected.
                :param diff_severity:
                    The severity to use for generating results.
                :param diff_message:
                    The message to use for generating results.
                :return:
                    An iterator returning results containing patches for the
                    file to correct.
                """
                if isinstance(output, str):
                    output = (output,)

                for string in output:
                    for diff in Diff.from_string_arrays(
                                file,
                                string.splitlines(keepends=True)).split_diff():
                        yield Result(self,
                                     diff_message,
                                     affected_code=(diff.range(filename),),
                                     diffs={filename: diff},
                                     severity=diff_severity)

            def process_output_regex(
                    self,
                    output,
                    filename,
                    file,
                    output_regex,
                    severity_map=MappingProxyType({
                        "error": RESULT_SEVERITY.MAJOR,
                        "Error": RESULT_SEVERITY.MAJOR,
                        "ERROR": RESULT_SEVERITY.MAJOR,
                        "warning": RESULT_SEVERITY.NORMAL,
                        "Warning": RESULT_SEVERITY.NORMAL,
                        "WARNING": RESULT_SEVERITY.NORMAL,
                        "warn": RESULT_SEVERITY.NORMAL,
                        "Warn": RESULT_SEVERITY.NORMAL,
                        "WARN": RESULT_SEVERITY.NORMAL,
                        "info": RESULT_SEVERITY.INFO,
                        "Info": RESULT_SEVERITY.INFO,
                        "INFO": RESULT_SEVERITY.INFO})):
                """
                Processes the executable's output using a regex.

                :param output:
                    The output of the program. This can be either a single
                    string or a sequence of strings.
                :param filename:
                    The filename of the file currently being corrected.
                :param file:
                    The contents of the file currently being corrected.
                :param output_regex:
                    The regex to parse the output with. It should use as many
                    of the following named groups (via ``(?P<name>...)``) to
                    provide a good result:

                    - line - The line where the issue starts.
                    - column - The column where the issue starts.
                    - end_line - The line where the issue ends.
                    - end_column - The column where the issue ends.
                    - severity - The severity of the issue.
                    - message - The message of the result.
                    - origin - The origin of the issue.

                    The groups ``line``, ``column``, ``end_line`` and
                    ``end_column`` don't have to match numbers only, they can
                    also match nothing, the generated ``Result`` is filled
                    automatically with ``None`` then for the appropriate
                    properties.
                :param severity_map:
                    A dict used to map a severity string (captured from the
                    ``output_regex`` with the named group ``severity``) to an
                    actual ``coalib.results.RESULT_SEVERITY`` for a result.
                :return:
                    An iterator returning results.
                """
                if isinstance(output, str):
                    output = (output,)

                for string in output:
                    for match in re.finditer(output_regex, string):
                        yield self._convert_output_regex_match_to_result(
                            match, filename, severity_map=severity_map)

            if options["output_format"] is None:
                # Check if user supplied a `process_output` override.
                if not (hasattr(klass, "process_output") and
                        callable(klass.process_output)):
                    raise ValueError("`process_output` not provided by given "
                                     "class.")
                # No need to assign to `process_output` here, the class mixing
                # below automatically does that.
            else:
                # Prevent people from accidentally defining `process_output`
                # manually, as this would implicitly override the internally
                # set-up `process_output`.
                if hasattr(klass, "process_output"):
                    raise ValueError("`process_output` is used by given class,"
                                     " but " + repr(options["output_format"]) +
                                     " output format was specified.")

                if options["output_format"] == "corrected":
                    process_output_args = {}
                    if "diff_severity" in options:
                        process_output_args["diff_severity"] = (
                            options["diff_severity"])
                    if "diff_message" in options:
                        process_output_args["diff_message"] = (
                            options["diff_message"])

                    process_output = partialmethod(
                        process_output_corrected, **process_output_args)

                elif options["output_format"] == "regex":
                    process_output_args = {
                        "output_regex": options["output_regex"]}
                    if "severity_map" in options:
                        process_output_args["severity_map"] = (
                            options["severity_map"])

                    process_output = partialmethod(
                        process_output_regex, **process_output_args)

                else:  # pragma: no cover
                    # This statement is never reached.
                    # Due to a bug in coverage we can't use `pass` here, as
                    # the ignore-pragma doesn't take up this else-clause then.
                    # https://bitbucket.org/ned/coveragepy/issues/483/partial-
                    # branch-coverage-pragma-no-cover
                    assert False

            @classmethod
            @contextmanager
            def _create_config(cls, filename, file, **kwargs):
                """
                Provides a context-manager that creates the config file if the
                user provides one and cleans it up when done with linting.

                :param filename:
                    The filename of the file.
                :param file:
                    The file contents.
                :param kwargs:
                    Section settings passed from ``run()``.
                :return:
                    A context-manager handling the config-file.
                """
                content = cls.generate_config(filename, file, **kwargs)
                if content is None:
                    yield None
                else:
                    tmp_suffix = options["config_suffix"]
                    with make_temp(suffix=tmp_suffix) as config_file:
                        with open(config_file, mode="w") as fl:
                            fl.write(content)
                        yield config_file

            @staticmethod
            def _filter_kwargs(metadata, kwargs):
                """
                Filter out kwargs using the given metadata. Means only
                parameters contained in the metadata specification are taken
                from kwargs and returned.

                :param metadata:
                    The signature specification.
                :param kwargs:
                    The kwargs to filter.
                :return:
                    The filtered kwargs.
                """
                return {key: kwargs[key]
                        for key in metadata.non_optional_params.keys() |
                            metadata.optional_params.keys()
                        if key in kwargs}

            def run(self, filename, file, **kwargs):
                # Get the **kwargs params to forward to `generate_config()`
                # (from `_create_config()`).
                generate_config_kwargs = self._filter_kwargs(
                    self._get_generate_config_metadata(), kwargs)

                with self._create_config(
                        filename,
                        file,
                        **generate_config_kwargs) as config_file:

                    # And now retrieve the **kwargs for `create_arguments()`.
                    create_arguments_kwargs = self._filter_kwargs(
                        self._get_create_arguments_metadata(), kwargs)

                    output = self._execute_command(
                        self.create_arguments(filename,
                                              file,
                                              config_file,
                                              **create_arguments_kwargs),
                        stdin="".join(file) if options["use_stdin"] else None)
                    output = tuple(output[i] for i in options["output_stream"])
                    if len(output) == 1:
                        output = output[0]

                    process_output_kwargs = self._filter_kwargs(
                        self._get_process_output_metadata(), kwargs)
                    return self.process_output(output, filename, file,
                                               **process_output_kwargs)

        # Mixin the linter into the user-defined interface, otherwise
        # `create_arguments` and other methods would be overridden by the
        # default version.
        class Linter(klass, LinterBase):
            pass

        return Linter

    return create_linter
