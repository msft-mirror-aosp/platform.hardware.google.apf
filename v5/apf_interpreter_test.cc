#include <stdint.h>
#include <string.h>
#include <gtest/gtest.h>

#ifdef __cplusplus
extern "C" {
#endif
int match_labels(const uint8_t* const target_name,
                 const int target_name_max_len, const uint8_t* const udp_payload,
                 const int udp_payload_len, const uint8_t** src);

#ifdef __cplusplus
}
#endif

namespace apf {

TEST(ApfInterpreterTest, EmptyTargetName) {
  const uint8_t empty_target_name[] = { 0 };
  const uint8_t udp_payload[] = {1, 2, 3};
  const uint8_t* src = udp_payload;
  EXPECT_EQ(match_labels(empty_target_name, 1, udp_payload, 3, &src), -1);
}

TEST(ApfInterpreterTest, MatchLabelWithoutNameCompression) {
  const uint8_t matched_target_name[] =
      {0x04, 0x5f, 0x4e, 0x4d, 0x54,   // qname1 = _NMT._TCP.LOCAL
       0x04, 0x5f, 0x54, 0x43, 0x50,
       0x05, 0x4c, 0x4f, 0x43, 0x41, 0x4c, 0x00};
  const int matched_target_name_len = sizeof(matched_target_name);
  const uint8_t udp_payload[] =
      {0x00, 0x00, 0x00, 0x00, // tid = 0x00, flags = 0x00,
       0x00, 0x01, // qdcount = 1
       0x00, 0x00, // ancount = 0
       0x00, 0x00, // nscount = 0
       0x00, 0x00, // arcount = 0
       0x04, 0x5f, 0x6e, 0x6d, 0x74,   // qname1 = _nmt._tcp.local
       0x04, 0x5f, 0x74, 0x63, 0x70,
       0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
       0x00, 0x0c, 0x00, 0x01 }; // type=PTR, class=0x0001
  const int udp_payload_len = sizeof(udp_payload);
  const uint8_t* src = udp_payload + 12;

  EXPECT_EQ(match_labels(matched_target_name, matched_target_name_len, udp_payload, udp_payload_len, &src), 1);
  EXPECT_EQ(udp_payload + 29, src);

  const uint8_t not_matched_target_name[] =
      {0x04, 0x5f, 0x4d, 0x4d, 0x4d,   // qname1 = _MMM._tcp.local
       0x04, 0x5f, 0x74, 0x63, 0x70,
       0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00};
  const int not_matched_target_name_len = sizeof(not_matched_target_name);
  src = udp_payload + 12;
  EXPECT_EQ(match_labels(not_matched_target_name, not_matched_target_name_len, udp_payload, udp_payload_len, &src), 0);
  EXPECT_EQ(udp_payload + 29, src);
}

TEST(ApfInterpreterTest, MatchLabelWithNameCompression) {
  const uint8_t matched_target_name[] =
      {0x01, 0x42, // qname1 = B.LOCAL
       0x05, 0x4c, 0x4f, 0x43, 0x41, 0x4c, 0x00};
  const int matched_target_name_len = sizeof(matched_target_name);
  const uint8_t udp_payload[] =
      {0x00, 0x00, 0x00, 0x00, // tid = 0x00, flags = 0x00,
       0x00, 0x02, // qdcount = 2
       0x00, 0x00, // ancount = 0
       0x00, 0x00, // nscount = 0
       0x00, 0x00, // arcount = 0
       0x01, 0x61, 0x01, 0x62,   // qname1 = a.b.local
       0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
       0x00, 0x01, 0x00, 0x01,  // type=A, class=0x0001
      0xc0, 0x0e, // qname2 = b.local (name compression)
      0x00, 0x01, 0x00, 0x01 }; // type=A, class=0x0001
  const int udp_payload_len = sizeof(udp_payload);
  const uint8_t* src = udp_payload + 27;
  EXPECT_EQ(match_labels(matched_target_name, matched_target_name_len, udp_payload, udp_payload_len, &src), 1);
  EXPECT_EQ(udp_payload + 29, src);
}

TEST(ApfInterpreterTest, MatchLabelWithinfIniteloop) {
  const uint8_t matched_target_name[] =
      {0x01, 0x42, // qname1 = B.LOCAL
       0x05, 0x4c, 0x4f, 0x43, 0x41, 0x4c, 0x00};
  const int matched_target_name_len = sizeof(matched_target_name);
  const uint8_t udp_payload[] =
      {0x00, 0x00, 0x00, 0x00, // tid = 0x00, flags = 0x00,
       0x00, 0x02, // qdcount = 2
       0x00, 0x00, // ancount = 0
       0x00, 0x00, // nscount = 0
       0x00, 0x00, // arcount = 0
       0x01, 0x61, 0x01, 0x62,   // qname1 = a.b.local
       0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
       0x00, 0x01, 0x00, 0x01,  // type=A, class=0x0001
       0xc0, 0x1b, // corrupted pointer cause infinite loop
       0x00, 0x01, 0x00, 0x01 }; // type=A, class=0x0001
  const int udp_payload_len = sizeof(udp_payload);
  const uint8_t* src = udp_payload + 27;
  EXPECT_EQ(match_labels(matched_target_name, matched_target_name_len, udp_payload, udp_payload_len, &src), -1);
}

}  // namespace apf
