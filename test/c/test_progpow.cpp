#include <iomanip>
#include <libethash/fnv.h>
#include <libethash/ethash.h>
#include <libethash/internal.h>
#include <libethash/io.h>

#ifdef WITH_CRYPTOPP

#include <libethash/sha3_cryptopp.h>

#else
#include <libethash/sha3.h>
#endif // WITH_CRYPTOPP

#ifdef _WIN32
#include <windows.h>
#include <Shlobj.h>
#endif

#include <iostream>
#include <fstream>
#include <vector>
#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>

using namespace std;
using byte = uint8_t;
using bytes = std::vector<byte>;
namespace fs = boost::filesystem;

// Just an alloca "wrapper" to silence uint64_t to size_t conversion warnings in windows
// consider replacing alloca calls with something better though!
#define our_alloca(param__) alloca((size_t)(param__))

// some functions taken from eth::dev for convenience.
static std::string bytesToHexString(const uint8_t *str, const uint64_t s)
{
	std::ostringstream ret;

	for (size_t i = 0; i < s; ++i)
		ret << std::hex << std::setfill('0') << std::setw(2) << std::nouppercase << (int) str[i];

	return ret.str();
}

static std::string blockhashToHexString(ethash_h256_t* _hash)
{
	return bytesToHexString((uint8_t*)_hash, 32);
}

static int fromHex(char _i)
{
	if (_i >= '0' && _i <= '9')
		return _i - '0';
	if (_i >= 'a' && _i <= 'f')
		return _i - 'a' + 10;
	if (_i >= 'A' && _i <= 'F')
		return _i - 'A' + 10;

	BOOST_REQUIRE_MESSAGE(false, "should never get here");
	return -1;
}

static bytes hexStringToBytes(std::string const& _s)
{
	unsigned s = (_s[0] == '0' && _s[1] == 'x') ? 2 : 0;
	std::vector<uint8_t> ret;
	ret.reserve((_s.size() - s + 1) / 2);

	if (_s.size() % 2)
		try
		{
			ret.push_back(fromHex(_s[s++]));
		}
		catch (...)
		{
			ret.push_back(0);
		}
	for (unsigned i = s; i < _s.size(); i += 2)
		try
		{
			ret.push_back((byte)(fromHex(_s[i]) * 16 + fromHex(_s[i + 1])));
		}
		catch (...){
			ret.push_back(0);
		}
	return ret;
}

static ethash_h256_t stringToBlockhash(std::string const& _s)
{
	ethash_h256_t ret;
	bytes b = hexStringToBytes(_s);
	memcpy(&ret, b.data(), b.size());
	return ret;
}

/* ProgPoW */

static void ethash_keccakf800(uint32_t state[25])
{
    for (int i = 0; i < 22; ++i)
        keccak_f800_round(state, i);
}

BOOST_AUTO_TEST_CASE(test_progpow_math)
{
	typedef struct {
		uint32_t a;
		uint32_t b;
		uint32_t exp;
	} mytest;

	mytest tests[] = {
		{20, 22, 42},
		{70000, 80000, 1305032704},
		{70000, 80000, 1},
		{1, 2, 1},
		{3, 10000, 196608},
		{3, 0, 3},
		{3, 6, 2},
		{3, 6, 7},
		{3, 6, 5},
		{0, 0xffffffff, 32},
		{3 << 13, 1 << 5, 3},
		{22, 20, 42},
		{80000, 70000, 1305032704},
		{80000, 70000, 1},
		{2, 1, 1},
		{10000, 3, 80000},
		{0, 3, 0},
		{6, 3, 2},
		{6, 3, 7},
		{6, 3, 5},
		{0, 0xffffffff, 32},
		{3 << 13, 1 << 5, 3},
	};

	for (int i = 0; i < sizeof(tests) / sizeof(mytest); i++) {
		uint32_t res = progpowMath(tests[i].a, tests[i].b, (uint32_t)i);
		BOOST_REQUIRE_EQUAL(res, tests[i].exp);
	}
}

BOOST_AUTO_TEST_CASE(test_progpow_merge)
{
	typedef struct {
		uint32_t a;
		uint32_t b;
		uint32_t exp;
	} mytest;
	mytest tests[] = {
		{1000000, 101, 33000101},
		{2000000, 102, 66003366},
		{3000000, 103, 6000103},
		{4000000, 104, 2000104},
		{1000000, 0, 33000000},
		{2000000, 0, 66000000},
		{3000000, 0, 6000000},
		{4000000, 0, 2000000},
	};
	for (int i = 0; i < sizeof(tests) / sizeof(mytest); i++) {
		uint32_t res = tests[i].a;
		merge(&res, tests[i].b, (uint32_t)i);
		BOOST_REQUIRE_EQUAL(res, tests[i].exp);
	}
}

BOOST_AUTO_TEST_CASE(test_progpow_keccak)
{
	// Test vectors from
	// https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-800-IntermediateValues.txt.
	uint32_t state[25] = {};
	const uint32_t expected_state_0[] = {0xE531D45D, 0xF404C6FB, 0x23A0BF99, 0xF1F8452F, 0x51FFD042,
		0xE539F578, 0xF00B80A7, 0xAF973664, 0xBF5AF34C, 0x227A2424, 0x88172715, 0x9F685884,
		0xB15CD054, 0x1BF4FC0E, 0x6166FA91, 0x1A9E599A, 0xA3970A1F, 0xAB659687, 0xAFAB8D68,
		0xE74B1015, 0x34001A98, 0x4119EFF3, 0x930A0E76, 0x87B28070, 0x11EFE996};
	ethash_keccakf800(state);
	for (size_t i = 0; i < 25; ++i)
		BOOST_REQUIRE_EQUAL(state[i], expected_state_0[i]);
	const uint32_t expected_state_1[] = {0x75BF2D0D, 0x9B610E89, 0xC826AF40, 0x64CD84AB, 0xF905BDD6,
		0xBC832835, 0x5F8001B9, 0x15662CCE, 0x8E38C95E, 0x701FE543, 0x1B544380, 0x89ACDEFF,
		0x51EDB5DE, 0x0E9702D9, 0x6C19AA16, 0xA2913EEE, 0x60754E9A, 0x9819063C, 0xF4709254,
		0xD09F9084, 0x772DA259, 0x1DB35DF7, 0x5AA60162, 0x358825D5, 0xB3783BAB};
	ethash_keccakf800(state);
	for (size_t i = 0; i < 25; ++i)
		BOOST_REQUIRE_EQUAL(state[i], expected_state_1[i]);
}

BOOST_AUTO_TEST_CASE(test_progpow_block0_verification) {
	// epoch 0
	ethash_light_t light = ethash_light_new(1045);
	ethash_h256_t seedhash = stringToBlockhash("5fc898f16035bf5ac9c6d9077ae1e3d5fc1ecc3c9fd5bee8bb00e810fdacbaa0");
	BOOST_ASSERT(light);
	ethash_return_value_t ret = progpow_light_compute(
		light,
		seedhash,
		0x50377003e5d830caU,
		1045
	);
	//ethash_h256_t difficulty = ethash_h256_static_init(0x25, 0xa6, 0x1e);
	//BOOST_REQUIRE(ethash_check_difficulty(&ret.result, &difficulty));
	ethash_light_delete(light);
}

BOOST_AUTO_TEST_CASE(test_progpow_keccak_f800) {
	ethash_h256_t seedhash;
	ethash_h256_t headerhash = stringToBlockhash("0000000000000000000000000000000000000000000000000000000000000000");

	{
		const std::string
			seedexp = "5dd431e5fbc604f499bfa0232f45f8f142d0ff5178f539e5a7800bf0643697af";
		const std::string header_string = blockhashToHexString(&headerhash);
		BOOST_REQUIRE_MESSAGE(true,
				"\nheader: " << header_string.c_str() << "\n");
		hash32_t result;
		for (int i = 0; i < 8; i++)
			result.uint32s[i] = 0;

		hash32_t header;
		memcpy((void *)&header, (void *)&headerhash, sizeof(headerhash));
		uint64_t nonce = 0x0;
		// keccak(header..nonce)
		hash32_t seed_256 = keccak_f800_progpow(header, nonce, result);
		uint64_t seed = (uint64_t)ethash_swap_u32(seed_256.uint32s[0]) << 32 | ethash_swap_u32(seed_256.uint32s[1]);
		uint64_t exp = 0x5dd431e5fbc604f4U;

		BOOST_REQUIRE_MESSAGE(seed == exp,
				"\nseed: " << seed << "exp: " << exp << "\n");
		ethash_h256_t out;
		memcpy((void *)&out, (void *)&seed_256, sizeof(result));
		const std::string out_string = blockhashToHexString(&out);
		BOOST_REQUIRE_MESSAGE(out_string == seedexp,
				"\nresult: " << out_string.c_str() << "\n");
	}
}

BOOST_AUTO_TEST_CASE(test_progpow_full_client_checks) {
	uint64_t full_size = ethash_get_datasize(0);
	uint64_t cache_size = ethash_get_cachesize(0);
	ethash_h256_t difficulty;
	ethash_return_value_t light_out;
	ethash_return_value_t full_out;
	ethash_h256_t hash = stringToBlockhash("0000000000000000000000000000000000000000000000000000000000000000");
	ethash_h256_t seed = stringToBlockhash("0000000000000000000000000000000000000000000000000000000000000000");

	// Set the difficulty
	ethash_h256_set(&difficulty, 0, 197);
	ethash_h256_set(&difficulty, 1, 90);
	for (int i = 2; i < 32; i++)
		ethash_h256_set(&difficulty, i, 255);

	ethash_light_t light = ethash_light_new_internal(cache_size, &seed);
	ethash_full_t full = ethash_full_new_internal(
		"./test_ethash_directory/",
		seed,
		full_size,
		light,
		NULL
	);
	{
		uint64_t nonce = 0x0;
		full_out = progpow_full_compute(full, hash, nonce, 0);
		BOOST_REQUIRE(full_out.success);

		const std::string
			exphead = "b3bad9ca6f7c566cf0377d1f8cce29d6516a96562c122d924626281ec948ef02",
			expmix = "f4ac202715ded4136e72887c39e63a4738331c57fd9eb79f6ec421c281aa8743";
		const std::string seed_string = blockhashToHexString(&seed);
		const std::string hash_string = blockhashToHexString(&hash);

		const std::string full_mix_hash_string = blockhashToHexString(&full_out.mix_hash);
		BOOST_REQUIRE_MESSAGE(full_mix_hash_string == expmix,
				"\nfull mix hash: " << full_mix_hash_string.c_str() << "\n");
		const std::string full_result_string = blockhashToHexString(&full_out.result);
		BOOST_REQUIRE_MESSAGE(full_result_string == exphead,
				"\nfull result: " << full_result_string.c_str() << "\n");
	}

	ethash_light_delete(light);
	ethash_full_delete(full);
	//fs::remove_all("./test_ethash_directory/");
}

BOOST_AUTO_TEST_CASE(test_progpow_light_client_checks) {
	uint64_t full_size = ethash_get_datasize(0);
	uint64_t cache_size = ethash_get_cachesize(0);
	ethash_return_value_t light_out;
	ethash_h256_t hash = stringToBlockhash("0000000000000000000000000000000000000000000000000000000000000000");
	ethash_h256_t seed = stringToBlockhash("0000000000000000000000000000000000000000000000000000000000000000");
	ethash_light_t light = ethash_light_new_internal(cache_size, &seed);
	{
		uint64_t nonce = 0x0;
		const std::string
			exphead = "b3bad9ca6f7c566cf0377d1f8cce29d6516a96562c122d924626281ec948ef02",
			expmix = "f4ac202715ded4136e72887c39e63a4738331c57fd9eb79f6ec421c281aa8743";
		const std::string hash_string = blockhashToHexString(&hash);

		light_out = progpow_light_compute_internal(light, full_size, hash, nonce, 0);
		BOOST_REQUIRE(light_out.success);

		const std::string light_result_string = blockhashToHexString(&light_out.result);
		BOOST_REQUIRE_MESSAGE(exphead == light_result_string,
				"\nlight result: " << light_result_string.c_str() << "\n"
						<< "exp result: " << exphead.c_str() << "\n");
		const std::string light_mix_hash_string = blockhashToHexString(&light_out.mix_hash);
		BOOST_REQUIRE_MESSAGE(expmix == light_mix_hash_string,
				"\nlight mix hash: " << light_mix_hash_string.c_str() << "\n"
						<< "exp mix hash: " << expmix.c_str() << "\n");
	}

	ethash_light_delete(light);
}

/// Defines a test case for ProgPoW hash() function. (from chfast/ethash/test/unittests/progpow_test_vectors.hpp)
struct progpow_hash_test_case
{
	int block_number;
	const char* header_hash_hex;
	const char* nonce_hex;
	const char* mix_hash_hex;
	const char* final_hash_hex;
};

progpow_hash_test_case progpow_hash_test_cases[] = {
	{0, "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000",
		"f4ac202715ded4136e72887c39e63a4738331c57fd9eb79f6ec421c281aa8743",
		"b3bad9ca6f7c566cf0377d1f8cce29d6516a96562c122d924626281ec948ef02"},
	{49, "b3bad9ca6f7c566cf0377d1f8cce29d6516a96562c122d924626281ec948ef02", "0000000006ff2c47",
		"7730596f128f675ef9a6bb7281f268e4077d302f2b9078da1ece4349248561dd",
		"0b9ed0c11157f1365143e329a6e1cea4248d9d6cb44b9c6daf492c7a076654a4"},
	{50, "0b9ed0c11157f1365143e329a6e1cea4248d9d6cb44b9c6daf492c7a076654a4", "00000000076e482e",
		"829136d4a704eb8d06da773f1a90466e7b5ed12119c44526f045bbff4475d891",
		"e2e881c5b893c2f1ef06b96a10cfcbcf7255b307f0818e7d30eb12b2edfc237b"},
	{99, "e2e881c5b893c2f1ef06b96a10cfcbcf7255b307f0818e7d30eb12b2edfc237b", "000000003917afab",
		"deb3d8b45bdc596c56aa37a5eba456f478c82e60e5c028ce95f2e654e4bb7b57",
		"9bdc2ad2286eaa051d6ca1f5196d2dd1c9a039f1d7ce3e1c856b793deed01778"},
	{29950, "9bdc2ad2286eaa051d6ca1f5196d2dd1c9a039f1d7ce3e1c856b793deed01778", "005d409dbc23a62a",
		"c01e6d339cc687c77f653b81c74cb9de8b595554f2c5db671a7dde3846d2fa01",
		"de0d693e597cf2fd70a4cfaa73f6baafc29e1eee695a81295b278c1116580b72"},
	{29999, "de0d693e597cf2fd70a4cfaa73f6baafc29e1eee695a81295b278c1116580b72", "005db5fa4c2a3d03",
		"8b664cdbf396a7a185446c93dddd6611f5a736b11097381ae6bea45e802cec16",
		"21ec5d1984a4fd4394b042aa96365085225d964727a45def245ceab326e28128"},
	{30000, "21ec5d1984a4fd4394b042aa96365085225d964727a45def245ceab326e28128", "005db8607994ff30",
		"276951d89c1ed262bcac00df4fb9bf7af36991532744a2e287b0b758a56e15aa",
		"dc070b76cc311cd82267f98936acbbbd3ec1c1ab25b55e2c885af6474e1e6841"},
	{30049, "dc070b76cc311cd82267f98936acbbbd3ec1c1ab25b55e2c885af6474e1e6841", "005e2e215a8ca2e7",
		"6248ba0157d0f0592dacfe2963337948fffb37f67e7451a6862c1321d894cebe",
		"6fdecf719e2547f585a6ee807d8237db8e9489f63d3f259ab5236451eaded433"},
	{30050, "6fdecf719e2547f585a6ee807d8237db8e9489f63d3f259ab5236451eaded433", "005e30899481055e",
		"512d8f2bb0441fcfa1764c67e8dbed2afcbe9141de4bbebc5b51e0661dede550",
		"cb1587a1c372642cbd9ce4c1ba2f433985d44c571a676a032bc1e8c1ad066e24"},
	{30099, "cb1587a1c372642cbd9ce4c1ba2f433985d44c571a676a032bc1e8c1ad066e24", "005ea6aef136f88b",
		"be0e7d6afa6edd483ccc304afa9bf0abaca5e0f037a4f05bf5550b9309d1d12c",
		"78be18f20569a834d839dad48e0e51d6df6b6537575f0ad29898c7cf357f12cb"},
	{59950, "78be18f20569a834d839dad48e0e51d6df6b6537575f0ad29898c7cf357f12cb", "02ebe0503bd7b1da",
		"b85be51fce670aa437f28c02ea4fd7995fa8b6ac224e959b8dbfb5bdbc6f77ce",
		"a68a620ba17e0cf2817bc4397cf4b85f5770983aa7b7931319a7f61bd6f905b1"},
	{59999, "a68a620ba17e0cf2817bc4397cf4b85f5770983aa7b7931319a7f61bd6f905b1", "02edb6275bd221e3",
		"ffe745a932c21c0704291bb416fe8bffec76621cd3434861885beab42cec1734",
		"9e6667a151ac6f5186a05cb20877a2b3df02317046256a762cb8ec2d96aa34f0"},
};

BOOST_AUTO_TEST_CASE(test_progpow_test_cases) {
	ethash_light_t light;
	uint32_t epoch = -1;
	for (int i = 0; i < sizeof(progpow_hash_test_cases) / sizeof(progpow_hash_test_case); i++)
	{
		progpow_hash_test_case *t;
		t = &progpow_hash_test_cases[i];
		const auto epoch_number = t->block_number / ETHASH_EPOCH_LENGTH;
		if (!light || epoch != epoch_number)
			light = ethash_light_new(t->block_number);
		epoch = epoch_number;
		ethash_h256_t hash = stringToBlockhash(t->header_hash_hex);
		uint64_t nonce = strtoul(t->nonce_hex, NULL, 16);
		ethash_return_value_t light_out = progpow_light_compute(light, hash, nonce, t->block_number);
		BOOST_REQUIRE_EQUAL(blockhashToHexString(&light_out.result), t->final_hash_hex);
		BOOST_REQUIRE_EQUAL(blockhashToHexString(&light_out.mix_hash), t->mix_hash_hex);
		printf("next...\n");
	}
	ethash_light_delete(light);
}
