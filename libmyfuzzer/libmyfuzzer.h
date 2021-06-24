struct feature_type {

  u8 original_value;

  double similarity_min;
  double similarity_mode;
  double similarity_mean;
  double similarity_near;
  set< pair<double, u8> > similarity_top;

  double difference_mean;

};

struct pattern_type {

  u32 from;
  u32 to;
  double mode;

  u8 placeholder;
  u8 loop;
  u8 raw;
  u8 assertion;
  set<u32> enumeration;
  set<u32> offset;
  set< pair<u32, u32> > size;

  pattern_type() {

    from = to = 0;
    mode = 0;
    placeholder = loop = raw = assertion = 0;

    enumeration.clear();
    offset.clear();
    size.clear();

  }

};

struct extra_data {
  u8* data;                           /* Dictionary token data   */
  u32 len;                            /* Dictionary token length */
  u32 hit_cnt;                        /* Use count in the corpus */
};

string type_str[] = {"raw", "loop", "assertion" , "enumeration", "offset", "size"};


inline u32 UR(u32 limit) {

  static u32 rand_cnt = 0;
  static s32 dev_urandom_fd = open("/dev/urandom", O_RDONLY);

  if (unlikely(!rand_cnt--)) {

    u32 seed[2];

    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");
    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

  }

  return random() % limit;

}


