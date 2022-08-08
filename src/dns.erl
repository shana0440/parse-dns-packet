-module(dns).
-export([start/0]).

-record(header, {
    id,                     % 16 bits
    query_or_response,      % 1 bit
    operation_code,         % 4 bits
    authoritative_answer,   % 1 bit
    truncated_message,      % 1 bit
    recursion_desired,      % 1 bit
    recursion_available,    % 1 bit
    reserved,               % 3 bits
    response_code,          % 4 bits
    question_count,         % 16 bits
    answer_count,           % 16 bits
    authority_count,        % 16 bits
    additional_count        % 16 bits
  }).

-record(question, {
    name,                   % dynamic
    type,                   % 16 bits
    class                   % 16 bits
  }).

-record(record, {
    name,                   % dynamic
    type,                   % 16 bits
    class,                  % 16 bits
    ttl,                    % 32 bits
    rdata_length,           % 16 bits
    rdata                   % dynamic
  }).

read_packet(File) ->
  {ok, Device} = file:open(File, [read, binary]),
  % {ok, Size} = file:position(Device, {eof, 0}),
  % io:fwrite("~p\n", [Size]),
  Header = parse_dns_header(Device),
  Questions = parse_dns_question_section(Device, [], Header#header.question_count),
  {ok, Pos} = file:position(Device, {cur, 0}),
  io:fwrite("pos: ~p\n", [Pos]),
  Answers = parse_records(Device, [], Header#header.answer_count),
  io:fwrite("~p\n", [Answers]),
  file:close(Device),
  Questions.

parse_dns_header(Device) ->
  {ok, HeaderBytes} = file:read(Device, 12),
  <<ID:16, QueryOrResponse:1, OperationCode:4,
    AuthoritativeAnswer:1, TruncatedMessage:1, RecursionDesired:1,
    RecursionAvailable:1, Reserved:3, ResponseCode:4, QuestionCount:16,
    AnswerCount:16, AuthorityCount:16, AdditionalCount:16>> = HeaderBytes,
  Header = #header{
    id = ID,
    query_or_response = if
      QueryOrResponse == 1 ->
        response;
      true ->
        query
      end,
    operation_code = OperationCode,
    authoritative_answer = AuthoritativeAnswer,
    truncated_message = TruncatedMessage,
    recursion_desired = RecursionDesired,
    recursion_available = RecursionAvailable,
    reserved = Reserved,
    response_code = ResponseCode,
    question_count = QuestionCount,
    answer_count = AnswerCount,
    authority_count = AuthorityCount,
    additional_count = AdditionalCount
  },
  Header.

parse_dns_question_section(_, Questions, 0) ->
  Questions;
parse_dns_question_section(Device, Questions, Count) ->
  QuestionName = parse_domain(Device, []),
  {ok, <<QuestionType:16, QuestionClass:16>>} = file:read(Device, 4),
  Question = #question{
    name = QuestionName,
    type = QuestionType,
    class = QuestionClass
  },
  parse_dns_question_section(Device, Questions ++ [Question], Count - 1).

parse_domain(Device, Domain) ->
  io:fwrite("start read count\n"),
  {ok, CountBinary} = file:read(Device, 1),
  <<Count:8>> = CountBinary,
  io:fwrite("count ~p\n", [Count]),
  if Count == 0 ->
    string:join(Domain, ".");
  true ->
    {ok, NameBinary} = file:read(Device, Count),
    Name = binary_to_list(NameBinary),
    parse_domain(Device, Domain ++ [Name])
  end.

parse_records(_, Records, 0) ->
  Records;
parse_records(Device, Records, Count) ->
  Record = parse_record(Device),
  io:fwrite("~p\n", Record),
  parse_records(Device, Records ++ [Record], Count - 1).

parse_record(Device) ->
  io:fwrite("start read record domain\n"),
  Name = parse_domain(Device, []),
  io:fwrite("domain ~p\n", [Name]),
  {ok, <<Type:16, Class:16, TTL:32, RDLength:16>>} = file:read(Device, 1 + 1 + 2 + 1),
  {ok, RDataBinary} = file:read(Device, RDLength),
  RData = binary_to_list(RDataBinary),
  Record = #record{
    name = Name,
    type = Type,
    class = Class,
    ttl = TTL,
    rdata_length = RDLength,
    rdata = RData
  },
  Record.

start() ->
  Questions = read_packet("../response_packet.txt"),
  io:fwrite("~p\n", [Questions]).