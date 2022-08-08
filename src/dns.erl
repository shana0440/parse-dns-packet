-module(dns).
-export([start/0]).

-record(packet, {
    header,
    questions,
    answers
  }).

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
  Header = parse_dns_header(Device),
  Questions = parse_dns_question_sections(Device, [], Header#header.question_count),
  Answers = parse_records(Device, [], Header#header.answer_count),
  file:close(Device),
  #packet{
    header = Header,
    questions = Questions,
    answers = Answers
  }.

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

parse_dns_question_sections(_, Questions, 0) ->
  Questions;
parse_dns_question_sections(Device, Questions, Count) ->
  Question = parse_dns_question_section(Device),
  parse_dns_question_sections(Device, Questions ++ [Question], Count - 1).

parse_dns_question_section(Device) ->
  QuestionName = parse_domain(Device, []),
  {ok, <<QuestionType:16, QuestionClass:16>>} = file:read(Device, 4),
  Question = #question{
    name = QuestionName,
    type = case QuestionType of
        1 -> 'A';
        2 -> 'NS';
        3 -> 'MD';
        4 -> 'MF';
        5 -> 'CNAME';
        6 -> 'SOA';
        7 -> 'MB';
        8 -> 'MG';
        9 -> 'MR';
        10 -> 'NULL';
        11 -> 'WKS';
        12 -> 'PTR';
        13 -> 'HINFO';
        14 -> 'MINFO';
        15 -> 'MX';
        16 -> 'TXT'
      end,
    class = case QuestionClass of
        1 -> 'IN';
        2 -> 'CS';
        3 -> 'CH';
        4 -> 'HS'
      end
  },
  Question.

parse_domain(Device, Domain) ->
  parse_domain(Device, Domain, false).

parse_domain(Device, Domain, JumpTo) ->
  {ok, <<Count:8>>} = file:read(Device, 1),
  if
    Count == 0 ->
      case JumpTo of
        false -> false;
        _ -> {ok, _} = file:position(Device, JumpTo)
      end,
      string:join(Domain, ".");
    % message compression indicate by first two bits are one.
    % refs: https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.4
    (Count band 192) == 192 ->
      {ok, <<OffsetEnd:8>>} = file:read(Device, 1),
      <<_:2, OffsetStart:6>> = <<Count:8>>,
      <<Offset:14>> = <<OffsetStart:6, OffsetEnd:8>>,
      {ok, CurrentPosition} = file:position(Device, cur),
      {ok, _} = file:position(Device, Offset),
      parse_domain(Device, Domain, CurrentPosition);
    true ->
      {ok, NameBinary} = file:read(Device, Count),
      Name = binary_to_list(NameBinary),
      parse_domain(Device, Domain ++ [Name], JumpTo)
  end.

parse_records(_, Records, 0) ->
  Records;
parse_records(Device, Records, Count) ->
  Record = parse_record(Device),
  parse_records(Device, Records ++ [Record], Count - 1).

parse_record(Device) ->
  Question = parse_dns_question_section(Device),
  {ok, <<TTL:32, RDLength:16>>} = file:read(Device, 4 + 2),
  {ok, RDataBinary} = file:read(Device, RDLength),
  RData = binary_to_list(RDataBinary),
  Record = #record{
    name = Question#question.name,
    type = Question#question.type,
    class = Question#question.class,
    ttl = TTL,
    rdata_length = RDLength,
    rdata = RData
  },
  Record.

start() ->
  Packet = read_packet("../google_response_packet.txt"),
  io:fwrite("header: ~p\n", [Packet#packet.header]),
  io:fwrite("questions: ~p\n", [Packet#packet.questions]),
  io:fwrite("answers: ~p\n", [Packet#packet.answers]).
