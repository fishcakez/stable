-module(cowboy_csrf).

%% token api

-export([token/1]).
-export([token_qs/1]).

%% cowboy_req body api

-export([has_body/1]).
-export([body_length/1]).
-export([init_stream/4]).
-export([stream_body/1]).
-export([stream_body/2]).
-export([skip_body/1]).
-export([body/1]).
-export([body/2]).
-export([body_qs/1]).
-export([body_qs/2]).
-export([multipart_data/1]).
-export([multipart_skip/1]).

%% cowboy_middlware callback

-export([execute/2]).

-type option() ::
    {header, binary()} | {qs_key, binary()} | {cowboy_cookie_session, term()} |
    {size, pos_integer()}.
-type options() :: [option()].
-type env_option() :: {cowboy_csrf, options()}.

-export_type([env_option/0]).

%% token api

-spec token(cowboy_req:req()) -> {{binary(), binary()}, cowboy_req:req()}.
token(Req) ->
    token(header, Req, <<"x-csrf-token">>).

-spec token_qs(cowboy_req:req()) -> {{binary(), binary()}, cowboy_req:req()}.
token_qs(Req) ->
    token(qs_key, Req, <<"csrf_token">>).

%% cowboy_req body api

-spec has_body(cowboy_req:req()) -> boolean().
has_body(Req) ->
    cowboy_req:has_body(Req).

-spec body_length(cowboy_req:req()) ->
    {undefined | non_neg_integer, cowboy_req:req()}.
body_length(Req) ->
    cowboy_req:body_length(Req).

-spec init_stream(fun(), any(), fun(), cowboy_req:req()) ->
    {ok, cowboy_req:req()}.
init_stream(TransferDecode, TransferState, ContentDecode, Req) ->
    cowboy_req:init_stream(TransferDecode, TransferState, ContentDecode, Req).

-spec stream_body(cowboy_req:req()) ->
    {ok, binary(), cowboy_req:req()} |
    {done, cowboy_req:req()} |
    {error, atom()}.
stream_body(Req) ->
    body_check(Req, fun cowboy_req:stream_body/1).

-spec stream_body(non_neg_integer(), cowboy_req:req()) ->
    {ok, binary(), cowboy_req:req()} |
    {done, cowboy_req:req()} |
    {error, atom()}.
stream_body(MaxLength, Req) ->
    body_check(Req, fun(Req2) -> cowboy_req:stream_body(MaxLength, Req2) end).

-spec body(cowboy_req:req()) ->
    {ok, binary(), cowboy_req:req()} | {error, atom()}.
body(Req) ->
    body_check(Req, fun cowboy_req:body/1).

-spec body(non_neg_integer() | infinity, cowboy_req:req()) ->
    {ok, binary(), cowboy_req:req()} | {error, atom()}.
body(MaxLength, Req) ->
    body_check(Req, fun(Req2) -> cowboy_req:body(MaxLength, Req2) end).

-spec skip_body(cowboy_req:req()) -> {ok, cowboy_req:req()} | {error, atom()}.
skip_body(Req) ->
    cowboy_req:skip_body(Req).

-spec body_qs(cowboy_req:req()) ->
    {ok, [{binary(), binary() | true}], cowboy_req:req()} | {error, atom()}.
body_qs(Req) ->
    case cowboy_req:body_qs(Req) of
         {ok, BodyList, Req2} ->
             body_qs_check(BodyList, Req2);
         {error, _Reason} = Error ->
             Error
    end.

-spec body_qs(non_neg_integer() | infinity, cowboy_req:req()) ->
    {ok, [{binary(), binary() | true}], cowboy_req:req()} | {error, atom()}.
body_qs(MaxLength, Req) ->
    case cowboy_req:body_qs(MaxLength, Req) of
         {ok, BodyList, Req2} ->
             body_qs_check(BodyList, Req2);
         {error, _Reason} = Error ->
             Error
    end.

-spec multipart_data(cowboy_req:req()) ->
    {headers, cowboy_http:headers(), cowboy_req:req()} |
    {body, binary(), cowboy_req:req()} |
    {end_of_part | eof, cowboy_req:req()} |
    {error, atom()}.
multipart_data(Req) ->
    body_check(Req, fun cowboy_req:multipart_data/1).

-spec multipart_skip(cowboy_req:req()) ->
    {ok, cowboy_req:req()}.
multipart_skip(Req) ->
    cowboy_req:multipart_skip(Req).

%% cowboy_middleware callback

execute(Req, Env) ->
    case get_opts(cowboy_csrf, Env) of
         {_, Opts} ->
             Req2 = cowboy_req:set_meta(cowboy_csrf_opts, Opts, Req),
            {ok, Req2, Env};
        false ->
            {ok, Req, Env}
    end.

%% internal.

token(OptName, Req, DefaultKey) ->
    {Opts, Req2} = cowboy_req:meta(cowboy_csrf_opts, Req, []),
    CookieInfo = lookup_opt(cowboy_cookie_session, Opts),
    {Token, Req3} = lookup_create_token(Req2, CookieInfo, Opts),
    Key = lookup_opt(OptName, Opts, DefaultKey),
    {{Key, Token}, Req3}.

body_check(Req, Fun) ->
    case body_check(Req) of
         {ok, Req2} ->
             Fun(Req2);
         {error, _Reason} = Error ->
             Error
    end.

body_check(Req) ->
    case cowboy_req:meta(csrf, Req, undefined) of
         {false, Req2} ->
             {ok, Req2};
         {undefined, Req2} ->
             body_check_cookie(Req2)
    end.

body_check_cookie(Req) ->
    {Opts, Req2} = cowboy_req:meta(cowboy_csrf_opts, Req, []),
    CookieInfo = lookup_opt(cowboy_cookie_session, Opts),
    case lookup_token(Req2, CookieInfo) of
         {undefined, _Req3} ->
             {error, csrf};
         {Token, Req3} ->
             HeaderName = lookup_opt(header, Opts, <<"x-csrf-token">>),
             body_check_header(HeaderName, Req3, Token)
    end.

body_check_header(HeaderName, Req, Token) ->
    case cowboy_req:header(HeaderName, Req, undefined) of
         {Token, Req2} ->
             Req3 = cowboy_req:set_meta(csrf, false, Req2),
             {ok, Req3};
         _Other ->
             {error, csrf}
    end.

body_qs_check(BodyList, Req) ->
    {Opts, Req2} = cowboy_req:meta(cowboy_csrf_opts, Req, []),
    CookieInfo = lookup_opt(cowboy_cookie_session, Opts),
    case lookup_token(Req2, CookieInfo) of
         {undefined, _Req3} ->
             {error, csrf};
         {Token, Req3} ->
             Key = lookup_opt(qs_key, Opts, <<"csrf_token">>),
             body_qs_check(BodyList, Req3, Key, Token)
    end.

body_qs_check(BodyList, Req, Key, Token) ->
    case lists:keytake(Key, 1, BodyList) of
         {value, {_Key, Token}, BodyList2} ->
             {ok, BodyList2, Req};
         _Other ->
             {error, csrf}
    end.

lookup_opt(Key, List) ->
    lookup_opt(Key, List, undefined).

lookup_opt(Key, List, Default) ->
    case lists:keyfind(Key, 1, List) of
         {_Key, Value} ->
             Value;
         false ->
             Default
    end.

lookup_create_token(Req, CookieKey, Opts) ->
    case lookup_token(Req, CookieKey) of
         {undefined, Req2} ->
             create_token(Req2, CookieKey, Opts);
         {_Token, _Req2} = Result ->
             Result
    end.

lookup_token(Req, CookieKey) ->
    case cowboy_cookie_session:get(CookieKey, Req) of
         {undefined, _Req2} = Result ->
             Result;
         {TokenBytes, Req2} ->
             Token = base64url:encode(TokenBytes),
             {Token, Req2}
    end.

create_token(Req, CookieKey, Opts) ->
    Size = lookup_opt(size, Opts, 32),
    TokenBytes = crypto:strong_rand_bytes(Size),
    Token = base64url:encode(TokenBytes),
    Req2 = cowboy_cookie_session:set(TokenBytes, CookieKey, Req),
    {Token, Req2}.

get_opts(Key, Env) ->
    case lists:keyfind(handler_opts, 1, Env) of
         {_, HandlerOpts} ->
             get_opts_handler(Key, Env, HandlerOpts);
         false ->
             lists:keyfind(Key, 1, Env)
    end.

get_opts_handler(Key, Env, HandlerOpts) ->
    case lists:keyfind(Key, 1, HandlerOpts) of
         {_Key, _Opts} = Result ->
             Result;
         false ->
             lists:keyfind(Key, 1, Env)
    end.
