%%	The contents of this file are subject to the Common Public Attribution
%%	License Version 1.0 (the “License”); you may not use this file except
%%	in compliance with the License. You may obtain a copy of the License at
%%	http://opensource.org/licenses/cpal_1.0. The License is based on the
%%	Mozilla Public License Version 1.1 but Sections 14 and 15 have been
%%	added to cover use of software over a computer network and provide for
%%	limited attribution for the Original Developer. In addition, Exhibit A
%%	has been modified to be consistent with Exhibit B.
%%
%%	Software distributed under the License is distributed on an “AS IS”
%%	basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
%%	License for the specific language governing rights and limitations
%%	under the License.
%%
%%	The Original Code is OpenACD.
%%
%%	The Initial Developers of the Original Code is
%%	Andrew Thompson and Micah Warren.
%%
%%	All portions of the code written by the Initial Developers are Copyright
%%	(c) 2008-2009 SpiceCSM.
%%	All Rights Reserved.
%%
%%	Contributor(s):
%%
%%	Jan Vincent Liwanag / eZuce <jvliwanag at ezuce dot com>
%%

-module(cpx_agent_wsock_handler).
-author("jvliwanag").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include_lib("OpenACD/include/log.hrl").
-include_lib("OpenACD/include/agent.hrl").

-export([init/3]).
-export([websocket_init/3, websocket_handle/3,
	websocket_info/3, websocket_terminate/3]).

-record(state, {nonce, conn}).

init({tcp, http}, _Req, _Opts) ->
	{upgrade, protocol, cowboy_http_websocket}.

websocket_init(_TransportName, Req, _Opts) ->
	{ok, Req, #state{}}.

websocket_handle({text, Msg}, Req, State) ->
	?DEBUG("Received on ws: ~p", [Msg]),
	J = {struct, P} = mochijson2:decode(Msg),
	GetVal = fun(N) -> proplists:get_value(N, P) end,
	F = list_to_existing_atom(binary_to_list(GetVal(<<"function">>))),
	Args = GetVal(<<"args">>),
	ReqId = GetVal(<<"request_id">>),
	ApiRes = handle_api(F, Args, State),
	{RespBin, State1} = case ApiRes of
		{error, not_local} ->
			{E, Out, C} = cpx_agent_connection:handle_json(State#state.conn, J),
			maybe_exit(E),
			{Out, State#state{conn = C}};
		_ ->
			{RespProps, State2} = case ApiRes of
				{ok, St} ->
					{[{request_id, ReqId},
						{success, true}], St};
				{ok, Result, St} ->
					{[{request_id, ReqId},
						{success, true},
						{result, Result}], St};
				{E, ErrCode, ErrMessage, St} ->
					maybe_exit(E),
					{[{request_id, ReqId},
						{success, false},
						{errcode, ErrCode},
						{message, ErrMessage}], St}
			end,
			{mochijson2:encode({struct, RespProps}), State2}
	end,
	{reply, {text, RespBin}, Req, State1};

websocket_handle(Data, Req, State) ->
	?DEBUG("Received non-text on ws: ~p", [Data]),
    {ok, Req, State}.

websocket_info(wsock_shutdown, Req, State) ->
	{shutdown, Req, State};
websocket_info({agent, M}, Req, State) ->
	{E, Out, C} = cpx_agent_connection:encode_cast(State#state.conn, M),
	maybe_exit(E),
	?DEBUG("Agent Event: ~p~n Output: ~p", [M, Out]),

	State1 = State#state{conn = C},
	case Out of
		undefined ->
			{ok, Req, State1};
		_ ->
			RespBin = mochijson2:encode(Out),
			{reply, {text, RespBin}, Req, State1}
	end;
websocket_info(_Info, Req, State) ->
	{ok, Req, State}.

websocket_terminate(_Reason, _Req, _State) ->
    ok.

%% Internal

handle_api(get_nonce, [], State) ->
	[E, N] = util:get_pubkey(),
	Salt = util:generate_salt(),
	Result = {struct, [{nonce, Salt}, {pubkey_e, list_to_binary(integer_to_list(E, 16))},
		{pubkey_n, list_to_binary(integer_to_list(N, 16))}]},
	{ok, Result, State#state{nonce=Salt}};

handle_api(login, [_, _], #state{nonce = undefined, conn = undefined} = State) ->
	{error, <<"MISSING_NONCE">>, <<"get nonce comes first">>, State};
handle_api(login, [UsernameBin, EncryptedPwdBin], #state{conn = undefined} = State) ->
	EncryptedPwd = binary_to_list(EncryptedPwdBin),

	InvalidCredsError = {exit, <<"INVALID_CREDENTIALS">>,
		<<"username or password invalid">>, State},

	case catch util:decrypt_password(EncryptedPwd) of
		{ok, Decrypted} ->
			Username = binary_to_list(UsernameBin),
			Nonce = binary_to_list(State#state.nonce),
			case catch lists:split(length(Nonce), Decrypted) of
				{Nonce, Password} ->
					case cpx_agent_connection:login(Username, Password) of
						{ok, Agent, Conn} ->
							State1 = State#state{conn = Conn},
							Res = {struct, [
								{profile, list_to_binary(Agent#agent.profile)},
								{security_level, Agent#agent.security_level},
								{timestamp, util:now()}]
							},
							{ok, Res, State1};
						{error, deny} ->
							InvalidCredsError;
						{error, duplicate} ->
							{error, <<"DUPLICATE_CONNECTION">>,
								<<"agent already logged in">>, State}
					end;
				_ ->
					InvalidCredsError
			end;
		_ ->
			InvalidCredsError
	end;
handle_api(login, [_, _], State) ->
	{exit, <<"DUP_LOGIN">>, <<"already logged in">>, State};

handle_api(_, _, _) ->
	{error, not_local}.

%% Internal

-spec maybe_exit(atom()) -> any().
maybe_exit(exit) ->
	self() ! wsock_shutdown;
maybe_exit(_) ->
	ok.

-ifdef(TEST).

init_test() ->
	?assertEqual(
		{upgrade, protocol, cowboy_http_websocket},
		cpx_agent_wsock_handler:init({tcp, http}, req, [])).


websocket_init_test() ->
	?assertEqual(
		{ok, req, #state{}},
		cpx_agent_wsock_handler:websocket_init(tcp, req, [])).

t_handle(ReqId, Fun, Args, State) ->
	Bin = iolist_to_binary(mochijson2:encode({struct, [
		{request_id, ReqId},
		{function, Fun},
		{args, Args}]})),
	cpx_agent_wsock_handler:websocket_handle({text, Bin}, req, State).

t_assert_success(ReqId, Fun, Args, State, NState) ->
	t_assert_success(ReqId, Fun, Args, State, undefined, NState).

t_assert_success(ReqId, Fun, Args, State, Result, NState) ->
	{reply, {text, Txt}, _Req, St} = t_handle(ReqId, Fun, Args, State),

	?assertEqual(NState, St),
	{struct, Props} = mochijson2:decode(Txt),
	GetVal = fun(N) -> proplists:get_value(N, Props) end,
	?assertEqual(ReqId, GetVal(<<"request_id">>)),
	?assertEqual(true, GetVal(<<"success">>)),

	case Result of
		undefined ->
			ok;
		_ ->
			%% allows you to use atoms as key names
			{struct, ResultProps} = mochijson2:decode(mochijson2:encode(Result)),
			{struct, RProps} = GetVal(<<"result">>),

			%% Should be recursive, but good enough for now
			?assertEqual(lists:sort(ResultProps), lists:sort(RProps))
	end.

t_assert_fail(ReqId, Fun, Args, State, ErrCode, Message) ->
	{reply, {text, Txt}, _Req, _State} = t_handle(ReqId, Fun, Args, State),
	{struct, Props} = mochijson2:decode(Txt),
	GetVal = fun(N) -> proplists:get_value(N, Props) end,
	?assertEqual(ReqId, GetVal(<<"request_id">>)),
	?assertEqual(false, GetVal(<<"success">>)),
	?assertEqual(ErrCode, GetVal(<<"errcode">>)),
	?assertEqual(Message, GetVal(<<"message">>)).

t_assert_fail_shutdown(ReqId, Fun, Args, State, ErrCode, Message) ->
	t_assert_fail(ReqId, Fun, Args, State, ErrCode, Message),
	Shutdown = receive wsock_shutdown -> true after 10 -> false end,
	?assert(Shutdown).


websocket_login_test_() ->
	{setup, fun() ->
		meck:new(util),
		meck:expect(util, get_pubkey, 0, [23, 989898]),
		meck:expect(util, generate_salt, 0, <<"noncey">>),
		meck:expect(util, decrypt_password, fun(<<"encryptedpassword">>) -> {ok, "nonceypassword"};
			(_) -> {error, decrypt_failed} end),
		meck:expect(util, now, 0, 12345),

		meck:new(cpx_agent_connection)
	end, fun(_) ->
		meck:unload(cpx_agent_connection),
		meck:unload(util)
	end, [{"get_nonce", fun() ->
		State = #state{nonce=undefined},
		PubKeyEHex = <<"17">>,
		PubKeyNHex = <<"F1ACA">>,
		t_assert_success(1, get_nonce, [],
			State, {struct, [{nonce, <<"noncey">>}, {pubkey_e, PubKeyEHex},
				{pubkey_n, PubKeyNHex}]}, State#state{nonce= <<"noncey">>})
	end},
	{"login already logged in", fun() ->
		t_assert_fail(1, login, [<<"username">>, <<"password">>],
			#state{nonce= <<"noncey">>, conn= fkconn}, <<"DUP_LOGIN">>,
			<<"already logged in">>)
	end},
	{"login w/o nonce", fun() ->
		t_assert_fail_shutdown(1, login, [<<"username">>, <<"password">>],
			#state{nonce=undefined}, <<"MISSING_NONCE">>,
			<<"get nonce comes first">>)
	end},
	{"login decrypt fail", fun() ->
		meck:expect(util, decrypt_password, 1, {error, decrypt_fail}),

		t_assert_fail_shutdown(1, login, [<<"username">>, <<"cantdecrypt">>],
			#state{nonce= <<"noncey">>}, <<"INVALID_CREDENTIALS">>,
			<<"username or password invalid">>)
	end},
	{"login wrong salt", fun() ->
		meck:expect(util, decrypt_password, 1, {ok, <<"wrongnoncepassword">>}),

		t_assert_fail_shutdown(1, login, [<<"username">>, <<"cantdecrypt">>],
			#state{nonce= <<"noncey">>}, <<"INVALID_CREDENTIALS">>,
			<<"username or password invalid">>)
	end},
	{"login success", fun() ->
		Agent = #agent{id = "agentId", login = "username", skills = [],
						profile = "Default", security_level = agent},

		meck:expect(util, decrypt_password, 1, {ok, "nonceypassword"}),
		meck:expect(cpx_agent_connection, login, 2, {ok, Agent, conn}),

		St = #state{nonce= <<"noncey">>, conn = undefined},

		t_assert_success(1, login, [<<"username">>, <<"encryptedpwd">>],
			St, {struct, [{profile, <<"Default">>}, {security_level, agent},
			{timestamp, 12345}]}, St#state{conn = conn}),
		?assert(meck:called(cpx_agent_connection, login, ["username", "password"], self()))
	end},
	{"login deny", fun() ->
		meck:expect(util, decrypt_password, 1, {ok, "nonceypassword"}),
		meck:expect(cpx_agent_connection, login, 2, {error, deny}),

		t_assert_fail_shutdown(1, login, [<<"username">>, <<"cantdecrypt">>],
			#state{nonce= <<"noncey">>}, <<"INVALID_CREDENTIALS">>,
			<<"username or password invalid">>)
	end},
	{"login duplicate", fun() ->
		meck:expect(util, decrypt_password, 1, {ok, "nonceypassword"}),
		meck:expect(cpx_agent_connection, login, 2, {error, duplicate}),

		t_assert_fail(1, login, [<<"username">>, <<"cantdecrypt">>],
			#state{nonce= <<"noncey">>}, <<"DUPLICATE_CONNECTION">>,
			<<"agent already logged in">>)
	end}
	]}.

websocket_api_test_() ->
	Conn = conn,
	St = #state{conn = Conn},

	{setup, fun() ->
		meck:new(cpx_agent_connection)
	end,
	fun(_) ->
		meck:unload(cpx_agent_connection)
	end,
	[{"ok/error api", fun() ->
		meck:expect(cpx_agent_connection, handle_json, 2,
			{ok, <<"{\"request_id\":1,\"success\":true}">>, conn2}),
		t_assert_success(1, some_api_fun, [<<"somearg">>], St, St#state{conn=conn2}),
		?assert(meck:called(cpx_agent_connection, handle_json, [conn,
			{struct, [{<<"request_id">>, 1},
				{<<"function">>, <<"some_api_fun">>},
				{<<"args">>, [<<"somearg">>]}]}]))
	end},
	{"exit api", fun() ->
		meck:expect(cpx_agent_connection, handle_json, 2,
			{exit, <<"{\"request_id\":1,\"success\":false,\"errcode\":\"E\",\"message\":\"M\"}">>, conn2}),
		t_assert_fail_shutdown(1, some_api_fun, [<<"somearg">>],
			St, <<"E">>, <<"M">>),
		?assert(meck:called(cpx_agent_connection, handle_json, [conn,
			{struct, [{<<"request_id">>, 1},
				{<<"function">>, <<"some_api_fun">>},
				{<<"args">>, [<<"somearg">>]}]}]))
	end}]}.

agent_event_test_() ->
	State = #state{conn=conn},
	RespJ = {struct, []},

	{setup, fun() ->
		meck:new(cpx_agent_connection)
	end,
	fun(_) ->
		meck:unload(cpx_agent_connection)
	end,
	[{"ok/error event", fun() ->
		meck:expect(cpx_agent_connection, encode_cast, 2,
			{ok, RespJ, conn2}),

		?assertEqual(
			{reply, {text, <<"{}">>}, req, #state{conn=conn2}},
			websocket_info({agent, some_event}, req, State)
		),

		?assert(meck:called(cpx_agent_connection, encode_cast, [conn,
			some_event]))
	end},
	{"ok/error event no resp", fun() ->
		meck:expect(cpx_agent_connection, encode_cast, 2,
			{ok, undefined, conn2}),

		?assertEqual(
			{ok, req, #state{conn=conn2}},
			websocket_info({agent, some_event}, req, State)
		),

		?assert(meck:called(cpx_agent_connection, encode_cast, [conn,
			some_event]))
	end},
	{"exit event", fun() ->
		meck:expect(cpx_agent_connection, encode_cast, 2,
			{exit, RespJ, conn2}),

		?assertEqual(
			{reply, {text, <<"{}">>}, req, #state{conn=conn2}},
			websocket_info({agent, some_event}, req, State)
		),

		?assert(meck:called(cpx_agent_connection, encode_cast, [conn,
			some_event])),
		Shutdown = receive wsock_shutdown -> true after 10 -> false end,
		?assert(Shutdown)
	end}
	]}.

shutdown_test() ->
	%% TODO clean-ups
	?assertEqual({shutdown, req, #state{}}, websocket_info(wsock_shutdown, req, #state{})).

-endif.