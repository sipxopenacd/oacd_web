%% Copyright (c) 2012 eZuce, Inc. All rights reserved.
%% Contributed to SIPfoundry under a Contributor Agreement
%%
%% This software is free software; you can redistribute it and/or modify it under
%% the terms of the Affero General Public License (AGPL) as published by the
%% Free Software Foundation; either version 3 of the License, or (at your option)
%% any later version.
%%
%% This software is distributed in the hope that it will be useful, but WITHOUT
%% ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
%% FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
%% details.

-module(cpx_agent_wsock_handler).
-author("jvliwanag").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include_lib("openacd/include/agent.hrl").

-export([init/3]).
-export([websocket_init/3, websocket_handle/3,
	websocket_info/3, websocket_terminate/3]).

%% TODO should go into config
-ifndef(TEST).
-define(TIMEOUT_MS, 10000).
-else.
-define(TIMEOUT_MS, 10).
-endif.

-record(state, {nonce,
	conn,
	rpc_mods=[] :: [atom()],
	info_handlers=[] :: [{M::atom(), F::atom()}],
	lrcvd_t = 0 :: pos_integer() %% Last Received time
}).

init({tcp, http}, _Req, _Opts) ->
	{upgrade, protocol, cowboy_http_websocket}.

websocket_init(_TransportName, Req, Opts) ->
	RpcModsOpt = proplists:get_value(rpc_mods, Opts, []),
	InfoHandlers = proplists:get_value(info_handlers, Opts, []),
	St = #state{lrcvd_t = util:now_ms(), info_handlers=InfoHandlers},
	send_timeout_check(),
	case cpx_hooks:trigger_hooks(wsock_auth, [Req]) of
		{ok, {Login, Req2}} ->
			case cpx_agent_connection:start(Login) of
				{ok, Agent, Conn} ->
					SLevel = Agent#agent.security_level,
					send(init_response(Login)),
					RpcMods = get_rpc_mods(SLevel, RpcModsOpt),
					{ok, Req2, St#state{conn=Conn, rpc_mods=RpcMods}};
				{error, Err} ->
					HandleData = case cpx_hooks:trigger_hooks(wsock_auth_error, [Err]) of
						{ok, D} ->
							D;
						_ ->
							[]
					end,
					send(init_error_response(Err, HandleData)),
					RpcMods = get_rpc_mods(agent, RpcModsOpt),
					{ok, Req2, St#state{rpc_mods=RpcMods}}
			end;
		{error, Err, HandleData} ->
			send(init_error_response(Err, HandleData)),
			RpcMods = get_rpc_mods(agent, RpcModsOpt),
			{ok, Req, St#state{rpc_mods=RpcMods}}
	end.

websocket_handle({text, Msg}, Req, State) ->
	try
		lager:debug("Received on ws: ~p", [Msg]),
		Mods = State#state.rpc_mods,
		{E, Out, C} = cpx_agent_connection:handle_json(State#state.conn, Msg, Mods),
		maybe_exit(E),
		State1 = State#state{conn=C, lrcvd_t=util:now_ms()},
		case Out of
			undefined ->
				{ok, Req, State1};
			_ ->
				{reply, {text, Out}, Req, State1}
		end
	catch
		T:Err ->
			Trace = erlang:get_stacktrace(),
			lager:error("Error on recv: ~p ~p:~p -- ~nTrace: ~p", [Msg, T, Err, Trace]),
			{shutdown, Req, State}
	end;

websocket_handle(Data, Req, State) ->
	lager:debug("Received non-text on ws: ~p", [Data]),
    {ok, Req, State}.

websocket_info(wsock_shutdown, Req, State) ->
	{shutdown, Req, State};
websocket_info({send, Bin}, Req, State) ->
	{reply, {text, Bin}, Req, State};
websocket_info(timeout_check, Req, State) ->
	Diff = util:now_ms() - State#state.lrcvd_t,
	%% TODO send message
	case Diff > ?TIMEOUT_MS of
		true ->
			{shutdown, Req, State};
		_ ->
			send_timeout_check(),
			{ok, Req, State}
	end;
websocket_info(M, Req, State) ->
	try handle_ws_info(State#state.info_handlers, State#state.conn, M) of
		{E, Out, C} ->
			maybe_exit(E),
			lager:debug("Agent Event: ~p~n Output: ~p", [M, Out]),

			State1 = State#state{conn = C},
			case Out of
				undefined ->
					{ok, Req, State1};
				_ ->
					RespBin = ejrpc2_json:encode(Out),
					{reply, {text, RespBin}, Req, State1}
			end;
		_ ->
			lager:warning("Received unhandled info: ~p", [M]),
			{ok, Req, State}
	catch
		T:Err ->
			Trace = erlang:get_stacktrace(),
			lager:error("Error on info ~p ~p:~p -- ~nTrace: ~p", [M, T, Err, Trace]),
			{shutdown, Req, State}
	end.

websocket_terminate(_Reason, _Req, _State) ->
    ok.

%% Internal

get_rpc_mods(SecurityLevel, RpcMods) ->
	SVal = get_security_sval(SecurityLevel),
	get_rpc_mods_by_sval(SVal, RpcMods, []).

get_rpc_mods_by_sval(_, [], Acc) ->
	lists:reverse(Acc);
get_rpc_mods_by_sval(SVal, [Mod|Rest], Acc) when is_atom(Mod) ->
	%% no option, always added
	get_rpc_mods_by_sval(SVal, Rest, [Mod|Acc]);
get_rpc_mods_by_sval(SVal, [{Mod, Opts}|Rest], Acc) when is_atom(Mod), is_list(Opts) ->
	Level = proplists:get_value(security_level, Opts, agent),
	ModSVal = get_security_sval(Level),
	Acc1 = case ModSVal > SVal of
		true -> Acc;
		_ ->
			Opts1 = proplists:delete(security_level, Opts),
			case Opts1 of
				[] -> [Mod|Acc];
				_ -> [{Mod, Opts1}|Acc]
			end
	end,
	get_rpc_mods_by_sval(SVal, Rest, Acc1).

get_security_sval(supervisor) -> 1;
get_security_sval(admin) -> 2;
get_security_sval(_) -> 0. %% agent level by default

handle_ws_info([], Conn, Msg) ->
	%% Default fallback
	cpx_agent_connection:encode_cast(Conn, Msg);
handle_ws_info([{M, F}|T], Conn, Msg) ->
	case M:F(Conn, Msg) of
		{_E, _Out, _C} = O ->
			O;
		_ ->
			handle_ws_info(T, Conn, Msg)
	end.


-spec maybe_exit(atom()) -> any().
maybe_exit(exit) ->
	self() ! wsock_shutdown;
maybe_exit(_) ->
	ok.

send(Bin) ->
	self() ! {send, Bin}.

send_timeout_check() ->
	erlang:send_after(?TIMEOUT_MS, self(), timeout_check).

init_error_response(Err, HandleData) ->
	Resp = {struct, [
		{username, null},
		{node, atom_to_binary(node(), utf8)},
		{server_time, util:now_ms()},
		{login_error, Err},
		{data, HandleData}
	]},
	ejrpc2_json:encode(Resp).

init_response(Username) ->
	StructUsername = case Username of
		U when is_list(U) ->
			list_to_binary(U);
		_ ->
			null
	end,
	Resp = {struct, [
		{username, StructUsername},
		{node, atom_to_binary(node(), utf8)},
		{server_time, util:now_ms()}
	]},
	ejrpc2_json:encode(Resp).

-ifdef(TEST).

init_test() ->
	?assertEqual(
		{upgrade, protocol, cowboy_http_websocket},
		cpx_agent_wsock_handler:init({tcp, http}, req, [])).


websocket_init_test_() ->
	{setup, fun() ->
		meck:new(cpx_hooks),
		meck:new(cpx_agent_connection),
		meck:new(util),

		meck:expect(util, now, 0, 12),
		meck:expect(util, now_ms, 0, 12345)
	end, fun(_) ->
		meck:unload(util),
		meck:unload(cpx_agent_connection),
		meck:unload(cpx_hooks)
	end, [fun() ->
		meck:expect(cpx_hooks, trigger_hooks, fun(wsock_auth, [req]) ->
			{error, unhandled, []} end),

		?assertEqual({ok, req, #state{conn=undefined, lrcvd_t=12345}},
			cpx_agent_wsock_handler:websocket_init(tcp, req, [])),

		TimeoutCheck = receive timeout_check -> true after 20 -> false end,
		?assert(TimeoutCheck)
	end, fun() ->
		meck:expect(cpx_hooks, trigger_hooks, fun(wsock_auth, [req]) ->
			{ok, {"agent", req}}; (wsock_auth_error, [noagent]) -> unhandled end),
		meck:expect(cpx_agent_connection, start, fun("agent") ->
			{error, noagent} end),

		?assertMatch({ok, req, #state{}},
			cpx_agent_wsock_handler:websocket_init(tcp, req, []))
	end, fun() ->
		meck:expect(cpx_hooks, trigger_hooks, fun(wsock_auth, [req]) ->
			{ok, {"agent", req}} end),
		meck:expect(cpx_agent_connection, start, fun("agent") ->
			{ok, #agent{id="agent",login="agent"}, conn} end),

		?assertMatch({ok, req, #state{conn=conn}},
			cpx_agent_wsock_handler:websocket_init(tcp, req, []))
	end, {"agent RPC handlers", fun() ->
		meck:expect(cpx_hooks, trigger_hooks, fun(wsock_auth, [req]) ->
			{error, unhandled, []} end),

		?assertMatch({ok, req, #state{conn=undefined, rpc_mods=[rpc1, rpc2]}},
			cpx_agent_wsock_handler:websocket_init(tcp, req,
				[{rpc_mods, [rpc1, {rpc2, [{security_level, agent}]},
				{sup_rpc, [{security_level, supervisor}]}]}]))
	end}, {"agent RPC handlers with opts", fun() ->
		meck:expect(cpx_hooks, trigger_hooks, fun(wsock_auth, [req]) ->
			{error, unhandled, []} end),

		?assertMatch({ok, req, #state{conn=undefined, rpc_mods=[rpc1, {rpc2, [{opt, val}]}]}},
			cpx_agent_wsock_handler:websocket_init(tcp, req,
				[{rpc_mods, [rpc1, {rpc2, [{security_level, agent}, {opt, val}]},
				{sup_rpc, [{security_level, supervisor}]}]}]))
	end}, {"supervisor RPC handlers", fun() ->
		meck:expect(cpx_hooks, trigger_hooks, fun(wsock_auth, [req]) ->
			{ok, {"agent", req}} end),

		meck:expect(cpx_agent_connection, start, fun("agent") ->
			{ok, #agent{id="agent",login="agent",security_level=supervisor}, conn} end),

		?assertMatch({ok, req, #state{rpc_mods=[rpc1, rpc2, sup_rpc]}},
			cpx_agent_wsock_handler:websocket_init(tcp, req,
				[{rpc_mods, [rpc1, {rpc2, [{security_level, agent}]},
					{sup_rpc, [{security_level, supervisor}]}]}]))
	end}, {"info handlers", fun() ->
		?assertMatch({ok, req, #state{info_handlers=[info_handler]}},
			cpx_agent_wsock_handler:websocket_init(tcp, req,
				[{info_handlers, [info_handler]}]))
	end}]}.

websocket_api_test_() ->
	Conn = conn,
	Mods = [mod1, mod2],
	St = #state{conn = Conn, rpc_mods=Mods},

	Now = 12345,

	{setup, fun() ->
		meck:new(cpx_agent_connection),
		meck:new(util),

		meck:expect(util, now_ms, 0, Now)
	end,
	fun(_) ->
		meck:unload(util),
		meck:unload(cpx_agent_connection)
	end,
	[{"ok with resp api", fun() ->
		Req = <<"{\"id\":1,\"method\":\"do_something\"}">>,
		Res = <<"{\"id\":1,\"result\":5}">>,
		meck:expect(cpx_agent_connection, handle_json, 3,
			{ok, Res, conn2}),

		?assertEqual({reply, {text, Res}, req, St#state{conn=conn2, lrcvd_t=Now}},
			websocket_handle({text, Req}, req, St)),
		?assert(meck:called(cpx_agent_connection, handle_json, [conn, Req, Mods], self()))
	end},
	{"ok no resp api", fun() ->
		Req = <<"{\"method\":\"do_something\"}">>,
		Res = undefined,
		meck:expect(cpx_agent_connection, handle_json, 3,
			{ok, Res, conn2}),

		?assertEqual({ok, req, St#state{conn=conn2, lrcvd_t=Now}},
			websocket_handle({text, Req}, req, St)),
		?assert(meck:called(cpx_agent_connection, handle_json, [conn, Req, Mods], self()))
	end},
	{"exit api", fun() ->
		Req = <<"{\"id\":1,\"method\":\"do_something\"}">>,
		Res = <<"{\"id\":1,\"result\":5}">>,
		meck:expect(cpx_agent_connection, handle_json, 3,
			{exit, Res, conn2}),

		?assertEqual({reply, {text, Res}, req, St#state{conn=conn2, lrcvd_t=Now}},
			websocket_handle({text, Req}, req, St)),
		?assert(meck:called(cpx_agent_connection, handle_json, [conn, Req, Mods], self())),
		Shutdown = receive wsock_shutdown -> true after 10 -> false end,
		?assert(Shutdown)
	end}]}.

agent_event_test_() ->
	State = #state{conn=conn},
	RespJ = {struct, []},

	CustRespJ = 5,
	CustRespS = ejrpc2_json:encode(CustRespJ),


	{setup, fun() ->
		meck:new(cpx_agent_connection),
		meck:new(info_handler)
	end,
	fun(_) ->
		meck:unload()
	end,
	[{"ok/error event", fun() ->
		meck:expect(cpx_agent_connection, encode_cast, 2,
			{ok, RespJ, conn2}),

		?assertEqual(
			{reply, {text, <<"{}">>}, req, #state{conn=conn2}},
			websocket_info({agent, some_event}, req, State)
		),

		?assert(meck:called(cpx_agent_connection, encode_cast, [conn,
			{agent, some_event}]))
	end},
	{"ok/error event no resp", fun() ->
		meck:expect(cpx_agent_connection, encode_cast, 2,
			{ok, undefined, conn2}),

		?assertEqual(
			{ok, req, #state{conn=conn2}},
			websocket_info({agent, some_event}, req, State)
		),

		?assert(meck:called(cpx_agent_connection, encode_cast, [conn,
			{agent, some_event}]))
	end},
	{"exit event", fun() ->
		meck:expect(cpx_agent_connection, encode_cast, 2,
			{exit, RespJ, conn2}),

		?assertEqual(
			{reply, {text, <<"{}">>}, req, #state{conn=conn2}},
			websocket_info({agent, some_event}, req, State)
		),

		?assert(meck:called(cpx_agent_connection, encode_cast, [conn,
			{agent, some_event}])),
		Shutdown = receive wsock_shutdown -> true after 0 -> false end,
		?assert(Shutdown)
	end},
	{"unhandled event", fun() ->
		meck:expect(cpx_agent_connection, encode_cast, 2,
			{error, unhandled}),

		?assertEqual(
			{ok, req, State},
			websocket_info(some_unhandled_info, req, State)
		)
	end},
	{"custom info handler - {M, F}", fun() ->
		meck:expect(info_handler, handle, 2, {ok, CustRespJ, conn3}),

		State1 = State#state{info_handlers=[{info_handler, handle}]},
		?assertEqual(
			{reply, {text, CustRespS}, req, State1#state{conn=conn3}},
			websocket_info(some_event, req, State1)
		),
		?assert(meck:called(info_handler, handle, [conn, some_event]))
	end}
	]}.

timeout_test_() ->
	{setup, fun() ->
		meck:new(util)
	end, fun(_) ->
		meck:unload(util)
	end, [fun() ->
		meck:expect(util, now_ms, 0, 25),
		?assertMatch(
			{ok, _, _}, websocket_info(timeout_check, req, #state{lrcvd_t=20})),
		TimeoutCheck = receive timeout_check -> true after 20 -> false end,
		?assert(TimeoutCheck)
	end, fun() ->
		meck:expect(util, now_ms, 0, 31),
		?assertMatch(
			{shutdown, _, _}, websocket_info(timeout_check, req, #state{lrcvd_t=20}))
	end]}.

shutdown_test() ->
	%% TODO clean-ups
	?assertEqual({shutdown, req, #state{}}, websocket_info(wsock_shutdown, req, #state{})).

-endif.
