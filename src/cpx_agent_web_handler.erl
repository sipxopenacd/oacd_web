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

-module(cpx_agent_web_handler).
-author("jvliwanag").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include_lib("OpenACD/include/log.hrl").

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

init_test() ->
	?assertEqual(
		{ok, req, none},
		cpx_agent_web_handler:init({tcp, http}, req, [])).

handle_test_() ->
	ReqBinStr = <<"{\"function\":\"check_cookie\"}">>,
	NewPid = util:zombie(),
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
		Pid = util:zombie(),

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