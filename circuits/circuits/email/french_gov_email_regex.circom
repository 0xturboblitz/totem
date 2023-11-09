pragma circom 2.1.5;

include "@zk-email/zk-regex-circom/circuits/regex_helpers.circom";

template FrenchGovEmailNameRegex(msg_bytes) {
	signal input msg[msg_bytes];
	signal output out;

	var num_bytes = msg_bytes+1;
	signal in[num_bytes];
	in[0]<==255;
	for (var i = 0; i < msg_bytes; i++) {
		in[i+1] <== msg[i];
	}

	component eq[7][num_bytes];
	component lt[4][num_bytes];
	component and[16][num_bytes];
	component multi_or[3][num_bytes];
	signal states[num_bytes+1][13];
	component state_changed[num_bytes];

	states[0][0] <== 1;
	for (var i = 1; i < 13; i++) {
		states[0][i] <== 0;
	}

	for (var i = 0; i < num_bytes; i++) {
		state_changed[i] = MultiOR(12);
		lt[0][i] = LessEqThan(8);
		lt[0][i].in[0] <== 65;
		lt[0][i].in[1] <== in[i];
		lt[1][i] = LessEqThan(8);
		lt[1][i].in[0] <== in[i];
		lt[1][i].in[1] <== 90;
		and[0][i] = AND();
		and[0][i].a <== lt[0][i].out;
		and[0][i].b <== lt[1][i].out;
		lt[2][i] = LessEqThan(8);
		lt[2][i].in[0] <== 97;
		lt[2][i].in[1] <== in[i];
		lt[3][i] = LessEqThan(8);
		lt[3][i].in[0] <== in[i];
		lt[3][i].in[1] <== 122;
		and[1][i] = AND();
		and[1][i].a <== lt[2][i].out;
		and[1][i].b <== lt[3][i].out;
		and[2][i] = AND();
		and[2][i].a <== states[i][1];
		multi_or[0][i] = MultiOR(2);
		multi_or[0][i].in[0] <== and[0][i].out;
		multi_or[0][i].in[1] <== and[1][i].out;
		and[2][i].b <== multi_or[0][i].out;
		and[3][i] = AND();
		and[3][i].a <== states[i][12];
		and[3][i].b <== multi_or[0][i].out;
		multi_or[1][i] = MultiOR(2);
		multi_or[1][i].in[0] <== and[2][i].out;
		multi_or[1][i].in[1] <== and[3][i].out;
		states[i+1][1] <== multi_or[1][i].out;
		state_changed[i].in[0] <== states[i+1][1];
		eq[0][i] = IsEqual();
		eq[0][i].in[0] <== in[i];
		eq[0][i].in[1] <== 66;
		and[4][i] = AND();
		and[4][i].a <== states[i][0];
		and[4][i].b <== eq[0][i].out;
		states[i+1][2] <== and[4][i].out;
		state_changed[i].in[1] <== states[i+1][2];
		eq[1][i] = IsEqual();
		eq[1][i].in[0] <== in[i];
		eq[1][i].in[1] <== 32;
		and[5][i] = AND();
		and[5][i].a <== states[i][1];
		and[5][i].b <== eq[1][i].out;
		states[i+1][3] <== and[5][i].out;
		state_changed[i].in[2] <== states[i+1][3];
		eq[2][i] = IsEqual();
		eq[2][i].in[0] <== in[i];
		eq[2][i].in[1] <== 111;
		and[6][i] = AND();
		and[6][i].a <== states[i][2];
		and[6][i].b <== eq[2][i].out;
		states[i+1][4] <== and[6][i].out;
		state_changed[i].in[3] <== states[i+1][4];
		eq[3][i] = IsEqual();
		eq[3][i].in[0] <== in[i];
		eq[3][i].in[1] <== 110;
		and[7][i] = AND();
		and[7][i].a <== states[i][4];
		and[7][i].b <== eq[3][i].out;
		states[i+1][5] <== and[7][i].out;
		state_changed[i].in[4] <== states[i+1][5];
		and[8][i] = AND();
		and[8][i].a <== states[i][3];
		and[8][i].b <== eq[1][i].out;
		states[i+1][6] <== and[8][i].out;
		state_changed[i].in[5] <== states[i+1][6];
		and[9][i] = AND();
		and[9][i].a <== states[i][6];
		and[9][i].b <== multi_or[0][i].out;
		and[10][i] = AND();
		and[10][i].a <== states[i][7];
		and[10][i].b <== multi_or[0][i].out;
		multi_or[2][i] = MultiOR(2);
		multi_or[2][i].in[0] <== and[9][i].out;
		multi_or[2][i].in[1] <== and[10][i].out;
		states[i+1][7] <== multi_or[2][i].out;
		state_changed[i].in[6] <== states[i+1][7];
		eq[4][i] = IsEqual();
		eq[4][i].in[0] <== in[i];
		eq[4][i].in[1] <== 106;
		and[11][i] = AND();
		and[11][i].a <== states[i][5];
		and[11][i].b <== eq[4][i].out;
		states[i+1][8] <== and[11][i].out;
		state_changed[i].in[7] <== states[i+1][8];
		and[12][i] = AND();
		and[12][i].a <== states[i][8];
		and[12][i].b <== eq[2][i].out;
		states[i+1][9] <== and[12][i].out;
		state_changed[i].in[8] <== states[i+1][9];
		eq[5][i] = IsEqual();
		eq[5][i].in[0] <== in[i];
		eq[5][i].in[1] <== 117;
		and[13][i] = AND();
		and[13][i].a <== states[i][9];
		and[13][i].b <== eq[5][i].out;
		states[i+1][10] <== and[13][i].out;
		state_changed[i].in[9] <== states[i+1][10];
		eq[6][i] = IsEqual();
		eq[6][i].in[0] <== in[i];
		eq[6][i].in[1] <== 114;
		and[14][i] = AND();
		and[14][i].a <== states[i][10];
		and[14][i].b <== eq[6][i].out;
		states[i+1][11] <== and[14][i].out;
		state_changed[i].in[10] <== states[i+1][11];
		and[15][i] = AND();
		and[15][i].a <== states[i][11];
		and[15][i].b <== eq[1][i].out;
		states[i+1][12] <== and[15][i].out;
		state_changed[i].in[11] <== states[i+1][12];
		states[i+1][0] <== 1 - state_changed[i].out;
	}

	component final_state_result = MultiOR(num_bytes+1);
	for (var i = 0; i <= num_bytes; i++) {
		final_state_result.in[i] <== states[i][7];
	}
	out <== final_state_result.out;

	signal is_consecutive[msg_bytes+1][2];
	is_consecutive[msg_bytes][1] <== 1;
	for (var i = 0; i < msg_bytes; i++) {
		is_consecutive[msg_bytes-1-i][0] <== states[num_bytes-i][7] * (1 - is_consecutive[msg_bytes-i][1]) + is_consecutive[msg_bytes-i][1];
		is_consecutive[msg_bytes-1-i][1] <== state_changed[msg_bytes-i].out * is_consecutive[msg_bytes-1-i][0];
	}
	signal is_substr0[msg_bytes][3];
	signal is_reveal0[msg_bytes];
	signal output reveal0[msg_bytes];
	for (var i = 0; i < msg_bytes; i++) {
		is_substr0[i][0] <== 0;
		is_substr0[i][1] <== is_substr0[i][0] + states[i+1][6] * states[i+2][7];
		is_substr0[i][2] <== is_substr0[i][1] + states[i+1][7] * states[i+2][7];
		is_reveal0[i] <== is_substr0[i][2] * is_consecutive[i][1];
		reveal0[i] <== in[i+1] * is_reveal0[i];
	}
}