/* Modification - Begin */
using namespace std;

#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <iostream>
#include <map>
#include <set>
#include <vector>
#include "../config.h"
#include "../debug.h"
#include "../alloc-inl.h"
#include "libmyfuzzer.h"


extern "C" u32 read_value(u8 *buf, u8 endian, u32 from, u32 to) {

  u32 value = 0;
  u32 weight = 1;
  u32 i;

  if (endian == 'B') {

    for (i = to; i + 1 >= from + 1; i--) {

      value += (buf[i] * weight);
      weight *= 0x100;

    }

  }

  if (endian == 'L') {

    for (i = from; i <= to; i++) {

      value += (buf[i] * weight);
      weight *= 0x100;

    }

  }

  return value;

}


extern "C" void write_value(u8 *buf, u8 endian, u32 from, u32 to, u32 value) {

  u32 i;

  if (endian == 'B') {

    for (i = to; i + 1 >= from + 1; i--) {
      
      buf[i] = value % 0x100;
      value /= 0x100;

    }

  }

  if (endian == 'L') {

    for (i = from; i <= to; i++) {

      buf[i] = value % 0x100;
      value /= 0x100;

    }

  }

}


extern "C" void change_value(u32 *value, u32 index, u32 replacer) {

  u32 mask;

  mask = ~(0xFF << (8 * index));
  *value &= mask;
  replacer <<= (8 * index);
  *value |= replacer;

}


extern "C" double coverage_similarity(u8 *vector1, u8 *vector2, u32 size, u32 *normal, u32 *probe, u32 *intersection) {

  double sim = 0;
  u32 allunion = 0;
  int i;

  *normal = *probe = *intersection = 0;

  for (i = 0; i < size; i++) {

    if (vector1[i] != 0) (*normal)++;
    if (vector2[i] != 0) (*probe)++;

    if (vector1[i] + vector2[i] != 0) allunion++;
    if (vector1[i] * vector2[i] != 0) (*intersection)++;

  }

  if (allunion > 0) sim = (double)(*intersection) / (double)(allunion);

  return sim;

}


extern "C" double frequency_difference(u8 *vector1, u8 *vector2, u32 size, u32 *frequency, u32 *coverage) {

  double diff = 0;
  int i;

  *frequency = *coverage = 0;

  for (i = 0; i < size; i++) {

    if (vector1[i] != vector2[i] && vector1[i] * vector2[i] != 0) (*frequency)++;
    if (vector1[i] != vector2[i]/* && vector1[i] * vector2[i] == 0*/) (*coverage)++;

  }

  if (*coverage > 0) diff = (double)(*frequency) / (double)(*coverage);

  return diff;

}


extern "C" void* create_feature_vector(void) {

  vector<feature_type> *features = new vector<feature_type>();
  return features;

}


extern "C" void destroy_feature_vector(void *features_wrapper) {

  vector<feature_type> *features = (vector<feature_type> *)(features_wrapper);
  delete features;

}


extern "C" void extract_feature(void *features_wrapper, u32 byte, u8 original_value, double *similarity, double *difference) {

  vector<feature_type> *features = (vector<feature_type> *)(features_wrapper);
  map< double, set<u8> > similarity_map;
  map< double, set<u8> > difference_map;
  map< double, set<u8> >::reverse_iterator similarity_riter;
  map< double, set<u8> >::reverse_iterator difference_riter;
  set<u8>::iterator u8_iter;
  feature_type feature;
  double average, mode;
  u32 j;

  feature.original_value = original_value;

  similarity_map.clear();
  difference_map.clear();

  for (j = 0; j <= 0xFF; j++) {

    if (similarity_map.find(similarity[j]) == similarity_map.end()) similarity_map[similarity[j]].clear();
    if (difference_map.find(similarity[j]) == difference_map.end()) difference_map[difference[j]].clear();

    similarity_map[similarity[j]].insert(j);
    difference_map[difference[j]].insert(j);

  }

  feature.similarity_min = (*similarity_map.begin()).first;
  feature.similarity_mean = 0;
  feature.similarity_mode = -1;
  feature.similarity_near = similarity[(original_value + 1) % 0x100];
  feature.similarity_top.clear();

  for (similarity_riter = similarity_map.rbegin(); similarity_riter != similarity_map.rend(); ++similarity_riter) {

    feature.similarity_mean += (*similarity_riter).first * ((*similarity_riter).second).size() / 0x100;

    if (mode < 0 || similarity_map[feature.similarity_mode].size() < ((*similarity_riter).second).size()) 
      feature.similarity_mode = (*similarity_riter).first;

    if ((*similarity_riter).first > (1 + feature.similarity_min) / 2) {

      for (u8_iter = (*similarity_riter).second.begin(); u8_iter != (*similarity_riter).second.end(); ++u8_iter)
        feature.similarity_top.insert(make_pair((*similarity_riter).first, *u8_iter));

    }

  }

  feature.difference_mean = 0;

  for (difference_riter = difference_map.rbegin(); difference_riter != difference_map.rend(); ++difference_riter) {

    feature.difference_mean += (*difference_riter).first * ((*difference_riter).second).size() / 0x100;

  }
  
  features->push_back(feature);

}


extern "C" void* create_pattern_vector(void) {

  vector<pattern_type> *patterns = new vector<pattern_type>();
  return patterns;

}


extern "C" void destroy_pattern_vector(void *patterns_wrapper) {

  vector<pattern_type> *patterns = (vector<pattern_type> *)(patterns_wrapper);
  delete patterns;

}


extern "C" void* copy_pattern_vector(void *patterns_src_wrapper) {

  vector<pattern_type> *patterns_src = (vector<pattern_type> *)(patterns_src_wrapper);
  vector<pattern_type> *patterns_dest = new vector<pattern_type>();

  patterns_dest->clear();
  patterns_dest->assign(patterns_src->begin(), patterns_src->end());

  return patterns_dest;

}


extern "C" void group_field(void *patterns_wrapper, void *features_wrapper) {

  vector<pattern_type> *patterns = (vector<pattern_type> *)(patterns_wrapper);
  vector<feature_type> *features = (vector<feature_type> *)(features_wrapper);
  vector<feature_type>::iterator features_iter;
  s32 from = 0, to = 0;
  double similarity_mode;
  pattern_type pattern;
  feature_type feature;
  u32 count;

  similarity_mode = features->begin()->similarity_mode;

  for (features_iter = features->begin(); ; ++features_iter) {

    if (features_iter != features->end()) feature = *features_iter;
    else feature.similarity_mode = -1;

    if (feature.similarity_mode != similarity_mode || features_iter - features->begin() >= from + 4) {

      to = features_iter - features->begin() - 1;

      if (to >= from) {

        pattern.from = from;
        pattern.to = to;
        pattern.mode = similarity_mode;
        pattern.placeholder = pattern.loop = pattern.raw = pattern.assertion = 0;
        pattern.enumeration.clear();
        pattern.offset.clear();
        pattern.size.clear();

        patterns->push_back(pattern);

      }

      from = features_iter - features->begin(); 

    }

    if (features_iter == features->end()) break;

    similarity_mode = feature.similarity_mode;

  }

  pattern.from = features->end() - features->begin();
  pattern.to = features->end() - features->begin();
  pattern.mode = 0;
  pattern.placeholder = 1;
  pattern.loop = pattern.raw = pattern.assertion = 0;
  pattern.enumeration.clear();
  pattern.offset.clear();
  pattern.size.clear();

  patterns->push_back(pattern);

}


extern "C" void* create_patterns_iterator(void *patterns_wrapper, void *begin_iter_wrapper, u32 *size) {

  vector<pattern_type> *patterns = (vector<pattern_type> *)(patterns_wrapper);
  vector<pattern_type>::iterator *begin_iter = (vector<pattern_type>::iterator *)(begin_iter_wrapper);
  vector<pattern_type>::iterator *patterns_iter = new vector<pattern_type>::iterator();

  if (begin_iter) *patterns_iter = *begin_iter;
  else *patterns_iter = patterns->begin();

  if (size) *size = patterns->size();

  return patterns_iter;

}


extern "C" void destroy_patterns_iterator(void *patterns_iter_wrapper) {

  vector<pattern_type>::iterator *patterns_iter = (vector<pattern_type>::iterator *)(patterns_iter_wrapper);
  delete patterns_iter;

}


extern "C" u8 validate_patterns_iterator(void *patterns_wrapper, void *patterns_iter_wrapper, u8 skip_placeholder) {

  vector<pattern_type> *patterns = (vector<pattern_type> *)(patterns_wrapper);
  vector<pattern_type>::iterator *patterns_iter = (vector<pattern_type>::iterator *)(patterns_iter_wrapper);

  if (*patterns_iter == patterns->end()) return 0;

  pattern_type pattern = **patterns_iter;

  if (!pattern.placeholder || !skip_placeholder) return 1;
  else return 0;

}


extern "C" void fetch_patterns_iterator(void *patterns_wrapper, void *patterns_iter_wrapper) {

  vector<pattern_type> *patterns = (vector<pattern_type> *)(patterns_wrapper);
  vector<pattern_type>::iterator *patterns_iter = (vector<pattern_type>::iterator *)(patterns_iter_wrapper);

  if (*patterns_iter != patterns->end()) (*patterns_iter)++;

}


extern "C" void create_testcase_for_loop(void *patterns_wrapper, u8 *out_buf, s32 out_len) {

  vector<pattern_type> *patterns = (vector<pattern_type> *)(patterns_wrapper);
  vector<pattern_type>::iterator *patterns_iter;
  int i, j;
  pattern_type pattern1, pattern2;
  u32 value1, value2, value;
 
  for (i = 0; i < patterns->size(); i++) {

    pattern1 = *(patterns->begin() + i);
    value1 = read_value(out_buf, 'L', pattern1.from, pattern1.to);

    for (j = i+1; j < patterns->size(); j++) {

      pattern2 = *(patterns->begin() + j);
      value2 = read_value(out_buf, 'L', pattern2.from, pattern2.to);
/*
      if ((value1 == value2 && pattern2.to - pattern2.from == pattern1.to - pattern1.from) || 
          (pattern1.mode == pattern2.mode && pattern1.mode != 1)) {

        switch (UR(4)) {

          case 0: value = 0; break;
          case 1: value = 0xFF; break;
          case 2: value = 1 << UR(0x10); break;
          case 3: value = 2 * UR(0x10); break;

        }
*/

//      if (value1 == value2 && pattern1.mode == pattern2.mode && pattern1.mode != 1) {

      if (/*(value1 == value2 && pattern2.to - pattern2.from == pattern1.to - pattern1.from) || 
          */(value1 == value2 && pattern1.mode == pattern2.mode && pattern1.mode != 1)) {

        if (UR(2)) value = 1 << UR(0x10);
        else if (UR(2)) value = 2 * UR(0x10);

        write_value(out_buf, 'L', pattern1.from, pattern1.to, value);
        write_value(out_buf, 'L', pattern2.from, pattern2.to, value);

      }

    }

  }

}


extern "C" void get_position_for_offset(void *current_iter_wrapper, void *insert_iter_wrapper, u8 repeat,
                                        u32 *from_position, u32 *to_position, u32 *insert_position) {

  vector<pattern_type>::iterator *current_iter = (vector<pattern_type>::iterator *)(current_iter_wrapper);
  vector<pattern_type>::iterator *insert_iter = (vector<pattern_type>::iterator *)(insert_iter_wrapper);
  pattern_type pattern_current = **current_iter;
  pattern_type pattern_insert = **insert_iter;

  *insert_position = pattern_insert.from;
  *from_position = pattern_current.from + (*insert_position <= pattern_current.from ? repeat : 0);
  *to_position = pattern_current.to + (*insert_position <= pattern_current.from ? repeat : 0);

}


extern "C" u8* create_testcase_for_offset(u32 insert_position, u8 repeat, u8 *in_buf, s32 in_len, s32 *out_len) {

  u8 *out_buf;
  u8 i;

  *out_len = in_len + repeat;
  out_buf = (u8 *)(ck_alloc(*out_len));
 
  memcpy(out_buf, in_buf, insert_position);
  memcpy(out_buf + insert_position + repeat, in_buf + insert_position, in_len - insert_position);

  for (i = 0; i < repeat; i++) {

    out_buf[insert_position+i] = 0x88;

  }

  return out_buf;

}


extern "C" void get_position_for_size(void *current_iter_wrapper, void *begin_iter_wrapper, void *end_iter_wrapper, u8 repeat,
                                      u32 *from_position, u32 *to_position, u32 *begin_position, u32 *end_position) {

  vector<pattern_type>::iterator *current_iter = (vector<pattern_type>::iterator *)(current_iter_wrapper);
  vector<pattern_type>::iterator *begin_iter = (vector<pattern_type>::iterator *)(begin_iter_wrapper);
  vector<pattern_type>::iterator *end_iter = (vector<pattern_type>::iterator *)(end_iter_wrapper);
  pattern_type pattern_current = **current_iter;
  pattern_type pattern_begin = **begin_iter;
  pattern_type pattern_end = **end_iter;

  *begin_position = pattern_begin.from;
  *end_position = pattern_end.to;

  *from_position = pattern_current.from + (*end_position <= pattern_current.from ? (*end_position - *begin_position + 1) * repeat : 0);
  *to_position = pattern_current.to + (*end_position <= pattern_current.from ? (*end_position - *begin_position + 1) * repeat : 0); 

}


extern "C" u8* create_testcase_for_size(u32 begin_position, u32 end_position, u8 repeat, u8 *in_buf, s32 in_len, s32 *out_len) {

  u8 *out_buf;
  u8 i;

  *out_len = in_len + (end_position - begin_position + 1) * repeat;
  out_buf = (u8 *)(ck_alloc(*out_len));

  memcpy(out_buf, in_buf, end_position + 1);

  for (i = 0; i < repeat; i++) {

    memcpy(out_buf + end_position + 1 + (end_position - begin_position + 1) * i, 
           in_buf + begin_position, end_position - begin_position + 1);

  }

  memcpy(out_buf + end_position + 1 + (end_position - begin_position + 1) * repeat,
         in_buf + end_position + 1, in_len - end_position - 1);

  return out_buf;

}


extern "C" void check_offset(void *current_iter_wrapper, void *insert_iter_wrapper, void *features_wrapper, u8 endian, 
                             double *similarity_near, double *similarity_mid, double similarity_adapt1, double similarity_adapt2) {

  vector<pattern_type>::iterator *current_iter = (vector<pattern_type>::iterator *)(current_iter_wrapper);
  vector<pattern_type>::iterator *insert_iter = (vector<pattern_type>::iterator *)(insert_iter_wrapper);
  vector<feature_type> *features = (vector<feature_type> *)(features_wrapper);
  pattern_type pattern_current = **current_iter;
  pattern_type pattern_insert = **insert_iter;
  vector<feature_type>::iterator features_iter;
  feature_type feature;

  if (endian == 'B') features_iter = features->begin() + pattern_current.from;
  else features_iter = features->begin() + pattern_current.to;

  feature = *features_iter;
  *similarity_near = feature.similarity_near;
  *similarity_mid = (1+feature.similarity_min)/2;

  if (*similarity_near < *similarity_mid && similarity_adapt1 > *similarity_mid && similarity_adapt2 < *similarity_mid) {

    pattern_current.offset.insert(pattern_insert.from);
    **current_iter = pattern_current;

  }

}


extern "C" void check_size(void *current_iter_wrapper, void *begin_iter_wrapper, void *end_iter_wrapper, void *features_wrapper, u8 endian, 
                           double *similarity_near, double *similarity_mid, double similarity_adapt1, double similarity_adapt2) {

  vector<pattern_type>::iterator *current_iter = (vector<pattern_type>::iterator *)(current_iter_wrapper);
  vector<pattern_type>::iterator *begin_iter = (vector<pattern_type>::iterator *)(begin_iter_wrapper);
  vector<pattern_type>::iterator *end_iter = (vector<pattern_type>::iterator *)(end_iter_wrapper);
  vector<feature_type> *features = (vector<feature_type> *)(features_wrapper);
  pattern_type pattern_current = **current_iter;
  pattern_type pattern_begin = **begin_iter;
  pattern_type pattern_end = **end_iter;
  vector<feature_type>::iterator features_iter;
  feature_type feature;

  if (endian == 'B') features_iter = features->begin() + pattern_current.from;
  else features_iter = features->begin() + pattern_current.to;

  feature = *features_iter;
  *similarity_near = feature.similarity_near;
  *similarity_mid = (1+feature.similarity_min)/2;

  if (*similarity_near < *similarity_mid && similarity_adapt1 > *similarity_mid && similarity_adapt2 < *similarity_mid) {

    pattern_current.size.insert(make_pair(pattern_begin.from, pattern_end.to));
    **current_iter = pattern_current;

  }

}


extern "C" void check_raw(void *patterns_iter_wrapper, void *features_wrapper) {

  vector<pattern_type>::iterator *patterns_iter = (vector<pattern_type>::iterator *)(patterns_iter_wrapper);
  vector<feature_type> *features = (vector<feature_type> *)(features_wrapper);
  pattern_type pattern = **patterns_iter;
  vector<feature_type>::iterator features_iter;
  feature_type feature;
  bool flag;
  u32 i;

  flag = true;
 
  for (i = pattern.from; i <= pattern.to; i++) {

    features_iter = features->begin() + i;
    feature = *features_iter;

    if (feature.similarity_min < 1.0) {

      flag = false;
      break; 

    }

  }

  if (flag) {

    pattern.raw = 1;
    **patterns_iter = pattern;
    
  }

}


extern "C" void check_assertion(void *patterns_iter_wrapper, void *features_wrapper) {

  vector<pattern_type>::iterator *patterns_iter = (vector<pattern_type>::iterator *)(patterns_iter_wrapper);
  vector<feature_type> *features = (vector<feature_type> *)(features_wrapper);
  pattern_type pattern = **patterns_iter;
  vector<feature_type>::iterator features_iter;
  feature_type feature;
  bool flag;
  u32 i;

  flag = true;

  for (i = pattern.from; i <= pattern.to; i++) {

    features_iter = features->begin() + i;
    feature = *features_iter;

    if (feature.similarity_top.size() != 1) {

      flag = false;
      break;

    }

  }

  if (flag) {

    pattern.assertion = 1;
    **patterns_iter = pattern;

  }

}


extern "C" void check_enumeration(void *patterns_iter_wrapper, void *features_wrapper, u8 *in_buf, s32 in_len) {

  vector<pattern_type>::iterator *patterns_iter = (vector<pattern_type>::iterator *)(patterns_iter_wrapper);
  vector<feature_type> *features = (vector<feature_type> *)(features_wrapper);
  set< pair<double, u8> >::iterator top_iter;
  pattern_type pattern = **patterns_iter;
  feature_type feature_current, feature_near;
  u32 i, j;
  u32 value;

  for (i = pattern.from; i <= pattern.to; i++) {

    feature_current = *(features->begin() + i);

    if (feature_current.similarity_top.size() <= 1 || feature_current.similarity_top.size() > FUZZER_ENUMERATION) continue;

    for (top_iter = feature_current.similarity_top.begin(); top_iter != feature_current.similarity_top.end(); ++top_iter) {

      value = read_value(in_buf, 'L', pattern.from, pattern.to);
      change_value(&value, i - pattern.from, (*top_iter).second);

      pattern.enumeration.insert(value);

    }

  }

  **patterns_iter = pattern;

}


extern "C" void check_loop(void *patterns_iter_wrapper, void *features_wrapper) {

  vector<pattern_type>::iterator *patterns_iter = (vector<pattern_type>::iterator *)(patterns_iter_wrapper);
  vector<feature_type> *features = (vector<feature_type> *)(features_wrapper);
  pattern_type pattern = **patterns_iter;
  vector<feature_type>::iterator features_iter;
  feature_type feature;
  bool flag;
  u32 i;

  flag = false;

  for (i = pattern.from; i <= pattern.to; i++) {

    features_iter = features->begin() + i;
    feature = *features_iter;

    if (feature.difference_mean > FUZZER_LOOP) {

      flag = true;
      break;

    }

  }

  if (flag) {

    pattern.loop = 1;
    **patterns_iter = pattern;

  }

}

extern "C" void export_patterns(void *patterns_wrapper, char *testcase, char *sync_id) {

  vector<pattern_type> *patterns = (vector<pattern_type> *)(patterns_wrapper);
  vector<pattern_type>::iterator patterns_iter;
  set<u32>::iterator u32_iter;
  set< pair<u32, u32> >::iterator u32_pair_iter;
  pattern_type pattern;
  string pattern_path;
  FILE *fout;
  u32 count, size, value;
  pair<u32, u32> value_pair;
  size_t idx;

  if (strcmp(sync_id, FUZZER_NAME) == 0) {

    idx = string(testcase).find("src:");

    if (idx == string::npos) pattern_path = getenv("PATTERN_PATH") + string("/id:000000");
    else pattern_path = getenv("PATTERN_PATH") + string("/id:") + string(testcase).substr(idx+4, 6);

  }

  if (strcmp(sync_id, "afl-master") == 0) {
  
    idx = string(testcase).find_last_of('/');
    pattern_path = getenv("PATTERN_PATH") + string(testcase).substr(idx, 10);

  }

//  pattern_path = getenv("PATTERN_PATH") + string(testcase).substr(string(testcase).find_last_of('/'), 10);

  fout = fopen(pattern_path.c_str(), "wb+");

  count = patterns->size();
  fwrite(&count, sizeof(u32), 1, fout);

  for (patterns_iter = patterns->begin(); patterns_iter != patterns->end(); ++patterns_iter) {

    pattern = *patterns_iter;

    fwrite(&pattern.from, sizeof(u32), 1, fout);
    fwrite(&pattern.to, sizeof(u32), 1, fout);
    fwrite(&pattern.mode, sizeof(double), 1, fout);  //new
    fwrite(&pattern.placeholder, sizeof(u8), 1, fout);
    fwrite(&pattern.loop, sizeof(u8), 1, fout);
    fwrite(&pattern.raw, sizeof(u8), 1, fout);
    fwrite(&pattern.assertion, sizeof(u8), 1, fout);

    size = pattern.enumeration.size();
    fwrite(&size, sizeof(u32), 1, fout);
    for (u32_iter = pattern.enumeration.begin(); u32_iter != pattern.enumeration.end(); ++u32_iter) {
      value = *u32_iter;
      fwrite(&value, sizeof(u32), 1, fout);
    }

    size = pattern.offset.size();
    fwrite(&size, sizeof(u32), 1, fout);
    for (u32_iter = pattern.offset.begin(); u32_iter != pattern.offset.end(); ++u32_iter) {
      value = *u32_iter;
      fwrite(&value, sizeof(u32), 1, fout);
    }

    size = pattern.size.size();
    fwrite(&size, sizeof(u32), 1, fout);
    for (u32_pair_iter = pattern.size.begin(); u32_pair_iter != pattern.size.end(); ++u32_pair_iter) {
      value_pair = *u32_pair_iter;
      fwrite(&value_pair.first, sizeof(u32), 1, fout);
      fwrite(&value_pair.second, sizeof(u32), 1, fout);
    }

  }

  fclose(fout);

}


extern "C" void* import_patterns(char *testcase, char *sync_id) {

  vector<pattern_type> *patterns;
  pattern_type pattern;
  string pattern_path;
  FILE *fin;
  u32 count, size, value;
  pair<u32, u32> value_pair;
  u32 i, j;
  size_t idx;

  if (strcmp(sync_id, FUZZER_NAME) == 0) {

    idx = string(testcase).find("src:");

    if (idx == string::npos) pattern_path = getenv("PATTERN_PATH") + string("/id:000000");
    else pattern_path = getenv("PATTERN_PATH") + string("/id:") + string(testcase).substr(idx+4, 6);

  }

  if (strcmp(sync_id, "afl-master") == 0) {
  
    idx = string(testcase).find_last_of('/');
    pattern_path = getenv("PATTERN_PATH") + string(testcase).substr(idx, 10);

  }

  if (access(pattern_path.c_str(), 0) == -1) return NULL;

  patterns = new vector<pattern_type>();

  fin = fopen(pattern_path.c_str(), "rb");

  fread(&count, sizeof(u32), 1, fin);

  for (i = 0; i < count; i++) {

    fread(&pattern.from, sizeof(u32), 1, fin);
    fread(&pattern.to, sizeof(u32), 1, fin);
    fread(&pattern.mode, sizeof(double), 1, fin);
    fread(&pattern.placeholder, sizeof(u8), 1, fin);
    fread(&pattern.loop, sizeof(u8), 1, fin);
    fread(&pattern.raw, sizeof(u8), 1, fin);
    fread(&pattern.assertion, sizeof(u8), 1, fin);

    pattern.enumeration.clear();
    fread(&size, sizeof(u32), 1, fin);
    for (j = 0; j < size; j++) { 
      fread(&value, sizeof(u32), 1, fin); 
      pattern.enumeration.insert(value); 
    }

    pattern.offset.clear();
    fread(&size, sizeof(u32), 1, fin);
    for (j = 0; j < size; j++) {
      fread(&value, sizeof(u32), 1, fin);
      pattern.offset.insert(value);
    }

    pattern.size.clear();
    fread(&size, sizeof(u32), 1, fin);
    for (j = 0; j < size; j++) {
      fread(&value_pair.first, sizeof(u32), 1, fin);
      fread(&value_pair.second, sizeof(u32), 1, fin);
      pattern.size.insert(value_pair);
    }

    patterns->push_back(pattern);

  }

  fclose(fin);

  return patterns;

}


extern "C" u8* create_testcase_for_explore(void *patterns_wrapper, void *new_patterns_wrapper, u8 *in_buf, s32 in_len, s32 *out_len,
                                           struct extra_data *extras, u32 extras_cnt, const char *debug, const char *testcase) {

  vector<pattern_type> *patterns = (vector<pattern_type> *)(patterns_wrapper);
  vector<pattern_type> *new_patterns = (vector<pattern_type> *)(new_patterns_wrapper);
  vector<pattern_type>::iterator patterns_iter;
  pattern_type pattern;
  u8 *out_buf, *new_out_buf;
  u32 field, type;
  set<u32>::iterator u32_iter;
  set< pair<u32, u32> >::iterator u32_pair_iter;
  u32 use_stacking;
  u32 i, j;

  *out_len = in_len;
  out_buf = (u8 *)(ck_alloc(*out_len));
  memcpy(out_buf, in_buf, *out_len);

  new_patterns->clear();
  new_patterns->assign(patterns->begin(), patterns->end());

  use_stacking = UR(0x10);

  create_testcase_for_loop(patterns, out_buf, *out_len);  // to be delete

  for (i = 0; i < use_stacking; ) {

    field = UR(patterns->size());
    type = UR(6);
    pattern = *(patterns->begin() + field);

    switch (type) {

      case 0: /* raw */

        if (pattern.raw) {

          i++;

        }

        break;

      case 1: /* loop */

//      if (pattern.loop) {

        create_testcase_for_loop(patterns, out_buf, *out_len);

        i++;

//      }

        break;

      case 2: /* assertion */

        if ((pattern.assertion || pattern.enumeration.size()) && extras_cnt) {

          u32 use_extra = UR(extras_cnt);
          u32 extra_len = extras[use_extra].len;
          u32 max_len = pattern.to - pattern.from + 1;

          memcpy(out_buf + pattern.from, extras[use_extra].data, extra_len <= max_len ? extra_len : max_len);

          i++;

        }

        break;

      case 3: /* enumeration */

        if (pattern.enumeration.size()) {

          u32 target = UR(pattern.enumeration.size());
          for (u32_iter = pattern.enumeration.begin(), j = 0; j < target; ++u32_iter, j++);
          u32 value = *u32_iter;

          write_value(out_buf, 'L', pattern.from, pattern.to, value);

          i++;

        }

        break;

      case 4: /* offset */

        if (pattern.offset.size()) {

          //u8 endian = (UR(2) ? 'B' : 'L');
          u8 endian = 'L'; //to be delete
          u8 repeat = 0;

          while (!repeat) repeat = UR(0x10);

          u32 target = UR(pattern.offset.size());

          for (u32_iter = pattern.offset.begin(), j = 0; j < target; ++u32_iter, j++);

          u32 insert_position = *u32_iter;
          u32 from_position = pattern.from + (insert_position <= pattern.from ? repeat : 0);
          u32 to_position = pattern.to + (insert_position <= pattern.from ? repeat : 0);

          u32 offset = read_value(out_buf, endian, from_position, to_position);

          new_out_buf = create_testcase_for_offset(insert_position, repeat, out_buf, *out_len, out_len);
          ck_free(out_buf);
          out_buf = new_out_buf;

          write_value(out_buf, endian, from_position, to_position, offset + repeat);

          vector<pattern_type> tmp_patterns;
          tmp_patterns.clear();

          u32 off_to_mod = 0;

          for (j = 0; j < (repeat-1)/4+1; j++) {

            pattern_type pattern_tmp;
            
            pattern_tmp.from = insert_position + 4*j;
            pattern_tmp.to = insert_position + (repeat < 4*j+3 ? repeat : 4*j+3);

            tmp_patterns.push_back(pattern_tmp);

            off_to_mod++;

          }

          for (patterns_iter = new_patterns->begin(); patterns_iter != new_patterns->end(); ++patterns_iter) {
 
            if (patterns_iter->from == insert_position) break;
            
            off_to_mod++;
 
          }

          new_patterns->insert(patterns_iter, tmp_patterns.begin(), tmp_patterns.end());

          for (patterns_iter = new_patterns->begin() + off_to_mod; patterns_iter != new_patterns->end(); ++patterns_iter) {

            pattern_type pattern_tmp;

            pattern_tmp = *patterns_iter;
            pattern_tmp.from += repeat;
            pattern_tmp.to += repeat;
            *patterns_iter = pattern_tmp;
         
          }

          i++;

        }

        break;

      case 5: /* size */

        if (pattern.size.size()) {

          //u8 endian = (UR(2) ? 'B' : 'L');
          u8 endian = 'L';  // to be delete
          u8 repeat = 0;

          while (!repeat) repeat = UR(0x10);

          u32 target = UR(pattern.size.size());
          for (u32_pair_iter = pattern.size.begin(), j = 0; j < target; ++u32_pair_iter, j++);

          u32 begin_position = u32_pair_iter->first;
          u32 end_position = u32_pair_iter->second;

          u32 from_position = pattern.from + (end_position <= pattern.from ? (end_position - begin_position + 1) * repeat : 0);
          u32 to_position = pattern.to + (end_position <= pattern.from ? (end_position - begin_position + 1) * repeat : 0);

          u32 size = read_value(out_buf, endian, from_position, to_position);

          new_out_buf = create_testcase_for_size(begin_position, end_position, repeat, out_buf, *out_len, out_len);

          ck_free(out_buf);
          out_buf = new_out_buf;

          write_value(out_buf, endian, from_position, to_position, size + repeat);

          vector<pattern_type> tmp_patterns;
          tmp_patterns.clear();

          u32 off_to_mod = 0;

          for (patterns_iter = new_patterns->begin(); patterns_iter != new_patterns->end(); ++patterns_iter) {

            if (patterns_iter->from < begin_position) {

              off_to_mod++;
              continue;

            }

            tmp_patterns.push_back(*patterns_iter);

            if (patterns_iter->to == end_position) break;

          }

          for (j = 0; j < repeat; j++) new_patterns->insert(new_patterns->begin() + off_to_mod, tmp_patterns.begin(), tmp_patterns.end());

          u32 count = 0;

          for (patterns_iter = new_patterns->begin() + off_to_mod; patterns_iter != new_patterns->end(); ++patterns_iter) {

            pattern_type pattern_tmp;

            pattern_tmp = *patterns_iter;
            pattern_tmp.from += count * (end_position - begin_position + 1);
            pattern_tmp.to += count * (end_position - begin_position + 1);

            if (patterns_iter->to == end_position && count < repeat) count++;

            *patterns_iter = pattern_tmp;

          }

          i++;

        }

        break;

    }

  }

  return out_buf;

}
/* Modification - End */
