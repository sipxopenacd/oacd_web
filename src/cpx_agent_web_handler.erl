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

-module(cpx_agent_web_handler).
-author("jvliwanag").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include_lib("openacd/include/log.hrl").

-export([init/3, handle/2, terminate/2]).

init({tcp, http}, Req, _Opts) ->
    {ok, Req, none}.

handle(Req, State) ->
	%% hmm, would be nice to use erlando/state monad
	{Method, Req2} = cowboy_http_req:method(Req) ,
	{HasBody, Req3} = cowboy_http_req:has_body(Req2),

	{ok, Req4} = handle_req(Method, HasBody, Req3),

	{ok, Req4, State}.

handle_req('POST', true, Req) ->
	{PostVals, Req2} = cowboy_http_req:body_qs(Req),
	{CpxId, Req3} = cowboy_http_req:cookie(<<"cpx_id">>, Req2),

	ReqBinStr = proplists:get_value(<<"request">>, PostVals),
	ReqJson = mochijson2:decode(ReqBinStr),

	TPid = case CpxId of
		undefined -> none;
		_ -> cpx_agent_web_listener:get_connection(CpxId)
	end,

	{Pid, Req4} =
		case TPid of
			none ->
				{ok, Id, P} = cpx_agent_web_listener:new_session(),
				{ok, ReqC} = cowboy_http_req:set_resp_cookie(<<"cpx_id">>, Id, [], Req3),
				{P, ReqC};
			P ->
				{P, Req3}
		end,
	{ok, RespJson} = cpx_agent_web_connection:handle_api(Pid, ReqJson),

	%% TODO doesn't need to
	RespBinStr = iolist_to_binary(mochijson2:encode(RespJson)),

	cowboy_http_req:reply(200, [], RespBinStr, Req4).
	% ok.

terminate(_Req, _State) ->
    ok.

-ifdef(TEST).

zombie() -> spawn(fun() -> receive headshot -> exit(headshot) end end).

init_test() ->
	?assertEqual(
		{ok, req, none},
		cpx_agent_web_handler:init({tcp, http}, req, [])).

handle_test_() ->
	ReqBinStr = <<"{\"function\":\"check_cookie\"}">>,
	NewPid = zombie(),
	{setup, fun() ->
		meck:new(cowboy_http_req),
		meck:expect(cowboy_http_req, method, 1, {'POST', req}),
		meck:expect(cowboy_http_req, has_body, 1, {true, req}),
		meck:expect(cowboy_http_req, body_qs, 1,
			{[{<<"request">>, ReqBinStr}], req}),
		meck:expect(cowboy_http_req, reply, 4, {ok, req}),
		meck:expect(cowboy_http_req, set_resp_cookie, 4, {ok, req}),

		meck:new(cpx_agent_web_listener),
		meck:expect(cpx_agent_web_listener, new_session, 0, {ok, <<"newid">>, NewPid}),

		meck:new(cpx_agent_web_connection)
	end,
	fun(_) ->
		meck:unload(cpx_agent_web_connection),
		meck:unload(cpx_agent_web_listener),
		meck:unload(cowboy_http_req)
	end,
	[{"absent cookie", fun() ->
		meck:expect(cowboy_http_req, cookie, 2, {undefined, req}),

		ApiResp = {struct, []},
		meck:expect(cpx_agent_web_connection, handle_api, 2, {ok, ApiResp}),

		{ok, _Req, _} = handle(req, state),

		?assert(meck:called(cpx_agent_web_connection, handle_api,
			[NewPid, {struct, [{<<"function">>, <<"check_cookie">>}]}],
			self())),
		?assert(meck:called(cowboy_http_req, set_resp_cookie,
			[<<"cpx_id">>, <<"newid">>, [], req], self())),
		?assert(meck:called(cowboy_http_req, reply,
			[200, [], <<"{}">>, req]))
	end},
	{"expired/invalid cookie", fun() ->
		meck:expect(cowboy_http_req, cookie, 2, {<<"expired">>, req}),
		meck:expect(cpx_agent_web_listener, get_connection, 1, none),

		ApiResp = {struct, []},
		meck:expect(cpx_agent_web_connection, handle_api, 2, {ok, ApiResp}),

		{ok, _Req, _} = handle(req, state),

		?assert(meck:called(cpx_agent_web_connection, handle_api,
			[NewPid, {struct, [{<<"function">>, <<"check_cookie">>}]}],
			self())),
		?assert(meck:called(cowboy_http_req, set_resp_cookie,
			[<<"cpx_id">>, <<"newid">>, [], req], self())),
		?assert(meck:called(cowboy_http_req, reply,
			[200, [], <<"{}">>, req]))
	end},
	{"valid cookie", fun() ->
		Pid = zombie(),

		meck:expect(cowboy_http_req, cookie, 2, {<<"alive">>, req}),
		meck:expect(cpx_agent_web_listener, get_connection, 1, Pid),

		ApiResp = {struct, []},
		meck:expect(cpx_agent_web_connection, handle_api, 2, {ok, ApiResp}),

		{ok, _Req, _} = handle(req, state),

		?assert(meck:called(cpx_agent_web_connection, handle_api,
			[Pid, {struct, [{<<"function">>, <<"check_cookie">>}]}],
			self())),
		?assert(meck:called(cowboy_http_req, set_resp_cookie,
			[<<"cpx_id">>, <<"newid">>, [], req], self())),
		?assert(meck:called(cowboy_http_req, reply,
			[200, [], <<"{}">>, req]))
	end}]}.

-endif.
