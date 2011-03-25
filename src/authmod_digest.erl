%%%----------------------------------------------------------------------
%%% File    : authmod_digest.erl
%%% Author  : Steven Downs <sdowns@oakmoon.net>
%%% Purpose : 
%%% Created : 2011/03/16 by by Steven Downs <sdowns@oakmoon.net>
%%%----------------------------------------------------------------------
-module(authmod_digest).
-author('sdowns@oakmoon.net').

-export([
              start/1
            , stop/0
            , auth/2
            , get_header/0
            , out/1
        ]).

-include("yaws.hrl").
-include("yaws_api.hrl").


-define(SERVER, ?MODULE).
-define(SUPERVISOR, yaws_sup).

-define(ENABLE_DEBUG, yes).

-ifdef(ENABLE_DEBUG).
-define(DEBUG(X), error_logger:info_report(io_lib:format("DEBUG (~p, ~p): ~p~n", [?MODULE, ?LINE, X]))).
-define(INFO(X), error_logger:info_report(X)).
-else.
-define(INFO(X), ignore).
-define(DEBUG(X), ignore).
-endif.

-define(WARNING(X), error_logger:warning_report(X)).
-define(ERROR(X), error_logger:error_report(X)).



start(Sconf) when is_record(Sconf, sconf) ->
    Opaque = Sconf#sconf.opaque,
	start_opaque(Opaque);

start(PasswordPlugin) when is_list(PasswordPlugin) ->
    {ok, undefined}.

start_opaque(Opaque) when is_list(Opaque) ->
    %% Process items in <opaque>
	if
        is_list(Opaque) ->
            PasswordPlugin = get_option("password_plugin", Opaque),
            start(PasswordPlugin);
        true ->
            throw(password_plugin_not_found)
    end.


stop() ->
    ?DEBUG("In stop/0").


out(Arg) ->
	?DEBUG("In out/1"),
    yaws_outmod:out(Arg).

auth(Arg, Auth) when is_record(Arg, arg),
                      is_record(Auth, auth) ->

    H = Arg#arg.headers,
    case H#headers.authorization of
       {_, _, "Digest " ++ _Data} ->
            ?DEBUG("Digest"),
            {true, {"User", [], []}};
        _ ->
            ?DEBUG("Request auth"),
            {appmod, ?MODULE}
    end.

get_header() -> 
	?DEBUG("In get_header/0"),
	{Header, Data} = create_header_www_authenticate_digest("Project Manager"),
    [Header ++ ": ", Data, ["\r\n"]].


get_option(Name, Options) when is_list(Options) ->
    case lists:keysearch(Name, 1, Options) of
        {value, {Name, Value}} ->
            Value;
        false ->
            throw(not_found)
    end.

% create the string for a 401 Unauthenticated response
create_header_www_authenticate_digest(Realm) ->
	Nonce = bin_to_hexstring(crypto:rand_bytes(16)),
	{"WWW-Authenticate", "Digest realm=\"" ++ Realm ++ "\", nonce=\"" ++ Nonce ++ "\", qop=\"auth\""}.

bin_to_hexstring(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) ||
    X <- binary_to_list(Bin)]).

-ifndef(ENABLE_DEBUG).
ignore(_) -> ok.
ignore(_,_) -> ok.
-endif.