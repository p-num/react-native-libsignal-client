import { Buffer } from "@craftzdog/react-native-buffer";
import { default as deepEql, default as deepEqual } from "deep-eql";
import { assert } from "typed-assert";
import { Aci, Pni } from "../../src";
import {
  ClientZkAuthOperations,
  ClientZkGroupCipher,
  ClientZkProfileOperations,
  GroupMasterKey,
  GroupSecretParams,
  GroupSendDerivedKeyPair,
  GroupSendEndorsement,
  GroupSendEndorsementsResponse,
  ProfileKey,
  ServerSecretParams,
  ServerZkAuthOperations,
  ServerZkProfileOperations,
} from "../../src/zkgroup";
import { throwsSync } from "./extentions";
import { test } from "./utils";
import { Platform } from "react-native";

const SECONDS_PER_DAY = 86400;

function hexToBuffer(hex: string) {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

export const testZkGroup = () => {
  const TEST_UUID = "dc249e7a-56ea-49cd-abce-aa3a0d65f6f0";
  const TEST_UUID_1 = "18c7e848-2213-40c1-bd6b-3b69a82dd1f5";
  const TEST_ARRAY_32 = hexToBuffer(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  );
  const TEST_ARRAY_32_1 = hexToBuffer(
    "6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283"
  );
  const TEST_ARRAY_32_2 = hexToBuffer(
    "c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7"
  );
  const TEST_ARRAY_32_3 = new Uint8Array([
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
  ]);
  const TEST_ARRAY_32_4 = new Uint8Array([
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
  ]);
  const TEST_ARRAY_32_5 = hexToBuffer(
    "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122"
  );

  test("Test auth with pni integration", async () => {
    const aci = Aci.fromUuid(TEST_UUID);
    const pni = Pni.fromUuid(TEST_UUID_1);

    const redemptionTime = 123456 * SECONDS_PER_DAY;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams =
      ServerSecretParams.generateWithRandom(TEST_ARRAY_32);

    // const serverSecretParams = new ServerSecretParams(
    //   new Uint8Array([
    //     0, 41, 21, 156, 144, 189, 9, 247, 146, 242, 219, 52, 247, 226, 57, 49,
    //     58, 196, 85, 48, 90, 192, 114, 250, 239, 177, 243, 200, 222, 145, 86,
    //     116, 15, 243, 30, 226, 241, 107, 0, 112, 160, 27, 111, 165, 78, 210,
    //     181, 87, 67, 219, 64, 89, 197, 1, 40, 48, 172, 196, 105, 245, 12, 66,
    //     197, 176, 4, 174, 243, 241, 207, 19, 78, 244, 5, 100, 184, 96, 213, 4,
    //     44, 156, 248, 96, 244, 223, 199, 58, 201, 242, 229, 155, 57, 92, 40,
    //     201, 234, 218, 122, 54, 64, 103, 53, 17, 248, 123, 181, 94, 216, 35, 15,
    //     57, 243, 19, 30, 224, 213, 69, 14, 190, 121, 114, 162, 4, 185, 108, 173,
    //     53, 122, 192, 14, 250, 104, 250, 202, 14, 96, 164, 202, 243, 189, 96,
    //     148, 83, 0, 233, 81, 21, 44, 162, 193, 48, 116, 92, 82, 168, 30, 248,
    //     192, 139, 74, 21, 13, 254, 190, 125, 252, 137, 182, 209, 137, 204, 249,
    //     130, 233, 36, 47, 6, 68, 212, 58, 51, 155, 132, 0, 31, 65, 80, 38, 197,
    //     36, 138, 116, 165, 3, 12, 63, 193, 130, 157, 49, 32, 54, 28, 201, 43,
    //     111, 82, 226, 217, 147, 221, 55, 63, 221, 149, 2, 49, 239, 113, 244,
    //     215, 74, 237, 109, 183, 6, 235, 240, 65, 163, 215, 89, 101, 4, 122, 114,
    //     218, 48, 232, 111, 57, 215, 225, 111, 110, 193, 207, 127, 247, 247, 76,
    //     120, 54, 13, 173, 27, 179, 0, 75, 53, 202, 246, 6, 151, 123, 55, 207, 0,
    //     97, 250, 181, 244, 154, 44, 158, 235, 76, 218, 65, 234, 51, 83, 133, 58,
    //     214, 239, 38, 217, 26, 0, 250, 21, 249, 145, 179, 10, 50, 14, 100, 255,
    //     196, 155, 182, 153, 69, 86, 36, 56, 173, 81, 166, 230, 64, 114, 81, 24,
    //     254, 247, 100, 46, 159, 110, 176, 32, 17, 241, 172, 169, 34, 40, 179,
    //     46, 29, 106, 15, 67, 162, 167, 252, 168, 5, 148, 119, 71, 87, 184, 27,
    //     113, 215, 232, 150, 203, 131, 6, 183, 58, 238, 64, 122, 209, 50, 209,
    //     226, 142, 113, 64, 238, 197, 196, 142, 59, 54, 31, 169, 115, 176, 9,
    //     133, 213, 29, 212, 114, 75, 181, 255, 1, 49, 245, 168, 151, 230, 100,
    //     203, 100, 223, 226, 14, 218, 208, 131, 101, 220, 95, 101, 116, 116, 180,
    //     191, 116, 12, 69, 40, 44, 126, 142, 26, 129, 15, 108, 6, 90, 55, 20,
    //     228, 143, 206, 108, 142, 100, 232, 82, 25, 159, 241, 204, 203, 71, 2,
    //     142, 242, 12, 243, 5, 172, 222, 40, 81, 151, 34, 126, 29, 26, 56, 173,
    //     176, 38, 217, 13, 98, 191, 50, 59, 164, 197, 92, 73, 174, 196, 75, 95,
    //     179, 204, 159, 144, 154, 70, 33, 112, 95, 178, 99, 13, 250, 166, 102,
    //     72, 179, 195, 254, 137, 123, 127, 50, 251, 18, 176, 72, 1, 153, 154, 32,
    //     141, 134, 207, 138, 119, 203, 233, 110, 177, 17, 146, 141, 11, 194, 81,
    //     174, 119, 118, 172, 140, 239, 16, 222, 210, 23, 41, 161, 49, 225, 131,
    //     71, 85, 70, 18, 73, 233, 13, 130, 100, 206, 109, 68, 56, 5, 7, 199, 105,
    //     250, 61, 173, 184, 169, 26, 111, 2, 20, 186, 36, 132, 144, 216, 199,
    //     142, 90, 55, 87, 130, 206, 121, 182, 49, 159, 232, 102, 220, 153, 15,
    //     250, 104, 239, 14, 200, 140, 22, 98, 189, 13, 247, 242, 13, 37, 68, 93,
    //     8, 115, 241, 233, 38, 29, 224, 231, 97, 41, 63, 225, 122, 44, 52, 11,
    //     246, 156, 142, 112, 74, 88, 46, 202, 29, 116, 233, 89, 86, 178, 216,
    //     170, 161, 11, 133, 161, 124, 92, 176, 21, 202, 168, 52, 221, 64, 212,
    //     176, 10, 56, 215, 161, 72, 128, 188, 199, 136, 46, 179, 186, 64, 5, 87,
    //     173, 67, 53, 200, 247, 157, 154, 252, 114, 79, 172, 185, 59, 49, 241,
    //     104, 140, 124, 104, 222, 16, 135, 54, 187, 122, 39, 165, 113, 102, 107,
    //     144, 176, 81, 237, 94, 208, 196, 199, 232, 14, 76, 82, 238, 162, 46,
    //     122, 244, 187, 117, 122, 18, 20, 103, 206, 199, 103, 239, 235, 123, 57,
    //     196, 222, 207, 42, 141, 165, 192, 173, 195, 86, 244, 151, 249, 17, 172,
    //     179, 219, 147, 191, 237, 186, 8, 58, 26, 225, 215, 103, 164, 143, 212,
    //     101, 91, 72, 181, 173, 1, 172, 126, 68, 134, 57, 226, 200, 134, 33, 254,
    //     121, 207, 160, 0, 136, 101, 155, 8, 74, 26, 46, 191, 90, 103, 221, 157,
    //     155, 48, 103, 9, 199, 45, 240, 198, 27, 197, 240, 251, 97, 19, 12, 153,
    //     165, 196, 254, 183, 196, 169, 220, 3, 148, 123, 137, 86, 193, 78, 40,
    //     124, 225, 191, 152, 67, 93, 56, 23, 71, 134, 202, 187, 12, 203, 15, 190,
    //     142, 97, 207, 181, 239, 64, 113, 62, 14, 22, 97, 102, 197, 208, 150,
    //     162, 124, 217, 128, 173, 156, 119, 119, 159, 15, 184, 7, 149, 161, 138,
    //     243, 108, 128, 6, 19, 232, 30, 69, 7, 149, 121, 182, 107, 245, 127, 39,
    //     105, 56, 10, 65, 161, 154, 200, 14, 238, 247, 232, 75, 238, 225, 43,
    //     194, 106, 224, 13, 163, 103, 17, 175, 237, 56, 102, 14, 241, 116, 36,
    //     123, 8, 96, 147, 196, 122, 50, 77, 66, 60, 160, 188, 122, 40, 188, 92,
    //     59, 29, 158, 0, 126, 120, 138, 69, 80, 141, 137, 91, 8, 165, 217, 101,
    //     200, 107, 107, 197, 67, 58, 81, 167, 164, 85, 84, 47, 104, 139, 254,
    //     234, 92, 177, 26, 135, 92, 234, 116, 0, 69, 126, 94, 191, 6, 3, 87, 227,
    //     65, 41, 93, 124, 230, 147, 203, 0, 0, 6, 61, 5, 244, 203, 23, 253, 152,
    //     135, 108, 208, 196, 160, 108, 39, 202, 90, 133, 95, 4, 188, 60, 209,
    //     224, 67, 107, 105, 253, 45, 235, 156, 42, 140, 166, 147, 198, 160, 19,
    //     94, 102, 2, 17, 70, 3, 182, 160, 140, 134, 204, 134, 127, 2, 131, 202,
    //     178, 88, 147, 75, 104, 89, 213, 187, 146, 28, 10, 53, 52, 129, 26, 181,
    //     103, 80, 106, 124, 252, 135, 143, 34, 247, 111, 241, 25, 114, 7, 26, 17,
    //     43, 135, 97, 18, 94, 225, 225, 2, 248, 115, 242, 121, 167, 20, 46, 99,
    //     87, 60, 33, 152, 235, 231, 73, 231, 30, 99, 207, 87, 204, 110, 22, 41,
    //     216, 12, 28, 204, 155, 100, 7, 224, 237, 188, 66, 244, 19, 226, 187,
    //     152, 126, 170, 142, 86, 229, 186, 253, 17, 107, 47, 89, 87, 192, 53,
    //     104, 132, 100, 212, 140, 8, 241, 135, 61, 149, 126, 4, 79, 249, 129,
    //     224, 8, 204, 106, 114, 116, 181, 111, 128, 23, 101, 197, 1, 212, 191, 8,
    //     5, 91, 85, 245, 252, 19, 223, 28, 236, 187, 191, 73, 34, 196, 78, 6,
    //     194, 133, 46, 34, 254, 137, 85, 194, 19, 210, 73, 34, 28, 100, 135, 238,
    //     9, 158, 246, 117, 247, 104, 181, 106, 44, 32, 115, 253, 121, 224, 159,
    //     232, 41, 197, 64, 219, 191, 109, 20, 37, 118, 161, 52, 235, 89, 248,
    //     187, 113, 7, 255, 113, 146, 16, 5, 215, 135, 201, 220, 236, 220, 17,
    //     210, 66, 13, 234, 209, 125, 146, 53, 232, 243, 63, 179, 221, 216, 72,
    //     87, 254, 156, 240, 1, 247, 218, 19, 26, 215, 87, 66, 218, 251, 37, 223,
    //     145, 82, 40, 163, 229, 170, 88, 160, 252, 59, 40, 232, 188, 180, 78,
    //     227, 74, 15, 49, 64, 0, 16, 26, 229, 246, 100, 254, 88, 87, 154, 230, 3,
    //     75, 213, 183, 112, 49, 180, 142, 192, 4, 102, 224, 184, 135, 144, 226,
    //     177, 118, 196, 86, 184, 5, 8, 46, 17, 211, 65, 96, 59, 79, 13, 70, 208,
    //     169, 219, 126, 84, 36, 221, 203, 10, 218, 225, 58, 220, 95, 26, 116,
    //     107, 88, 88, 57, 32, 9, 45, 249, 62, 138, 193, 42, 68, 48, 183, 54, 244,
    //     92, 64, 232, 114, 30, 115, 10, 73, 177, 182, 185, 70, 192, 87, 92, 94,
    //     145, 223, 149, 132, 12, 187, 142, 28, 87, 161, 142, 162, 159, 166, 49,
    //     249, 174, 54, 245, 117, 69, 227, 38, 37, 68, 131, 7, 106, 45, 130, 109,
    //     49, 16, 102, 136, 109, 15, 98, 194, 176, 3, 44, 198, 37, 61, 189, 42,
    //     83, 73, 217, 227, 83, 82, 170, 245, 200, 45, 128, 201, 174, 103, 210,
    //     98, 184, 89, 205, 166, 75, 12, 69, 253, 44, 215, 153, 170, 148, 71, 21,
    //     233, 240, 179, 21, 240, 83, 145, 113, 65, 231, 255, 167, 139, 251, 13,
    //     167, 6, 182, 54, 84, 100, 102, 11, 152, 75, 171, 174, 147, 153, 249,
    //     221, 65, 0, 59, 12, 71, 1, 126, 140, 142, 233, 183, 41, 107, 23, 205,
    //     167, 133, 68, 154, 158, 19, 32, 73, 23, 54, 46, 137, 199, 205, 202, 185,
    //     10, 129, 119, 59, 159, 192, 146, 4, 185, 131, 30, 12, 29, 206, 228, 131,
    //     173, 171, 15, 103, 56, 75, 135, 201, 92, 49, 84, 41, 98, 73, 132, 86,
    //     171, 17, 79, 163, 64, 155, 228, 60, 58, 229, 102, 197, 169, 252, 188,
    //     46, 221, 27, 103, 42, 145, 176, 203, 65, 0, 214, 107, 135, 190, 5, 68,
    //     226, 250, 131, 224, 157, 166, 134, 61, 89, 92, 77, 51, 103, 200, 175,
    //     138, 65, 214, 51, 237, 75, 142, 13, 137, 165, 5, 192, 91, 211, 18, 63,
    //     123, 76, 38, 76, 103, 9, 180, 161, 246, 111, 103, 180, 187, 114, 33,
    //     103, 202, 232, 245, 14, 200, 97, 35, 18, 136, 68, 76, 244, 58, 216, 129,
    //     221, 119, 145, 120, 217, 139, 102, 99, 12, 153, 2, 132, 211, 12, 27,
    //     225, 160, 19, 165, 12, 20, 51, 139, 134, 225, 186, 200, 10, 93, 119,
    //     183, 206, 254, 16, 167, 162, 153, 188, 223, 192, 81, 60, 203, 171, 183,
    //     125, 218, 158, 148, 31, 255, 44, 151, 50, 34, 236, 18, 29, 125, 3, 162,
    //     80, 28, 194, 69, 255, 101, 1, 99, 168, 22, 74, 141, 24, 47, 183, 189,
    //     27, 21, 122, 118, 247, 120, 203, 80, 119, 56, 192, 156, 249, 29, 2, 216,
    //     97, 189, 8, 167, 172, 16, 253, 224, 153, 100, 192, 230, 192, 54, 164,
    //     236, 11, 39, 60, 145, 156, 37, 228, 237, 130, 59, 112, 186, 89, 237, 1,
    //     177, 170, 188, 83, 34, 214, 32, 92, 89, 187, 165, 131, 23, 123, 7, 114,
    //     195, 127, 70, 66, 227, 91, 16, 40, 142, 22, 39, 106, 58, 197, 122, 6,
    //     168, 96, 170, 177, 156, 225, 3, 159, 96, 57, 224, 154, 14, 158, 222, 97,
    //     147, 238, 21, 174, 17, 247, 81, 186, 248, 105, 194, 231, 40, 126, 158,
    //     14, 92, 10, 136, 48, 254, 241, 5, 191, 18, 13, 146, 104, 41, 68, 108,
    //     255, 223, 212, 215, 13, 252, 89, 198, 248, 87, 213, 42, 5, 77, 176, 132,
    //     4, 104, 132, 151, 203, 24, 13, 207, 169, 144, 19, 135, 0, 102, 24, 51,
    //     31, 134, 55, 235, 111, 127, 212, 131, 175, 210, 61, 137, 94, 29, 221,
    //     34, 47, 6, 75, 202, 126, 100, 179, 111, 254, 232, 248, 196, 30, 201, 6,
    //     114, 171, 132, 63, 181, 136, 146, 89, 130, 140, 106, 34, 241, 92, 232,
    //     171, 163, 35, 85, 191, 242, 132, 117, 190, 114, 172, 194, 8, 163, 180,
    //     210, 241, 135, 244, 110, 156, 108, 85, 20, 193, 198, 46, 51, 3, 214, 90,
    //     66, 80, 118, 13, 98, 179, 134, 155, 247, 236, 249, 2, 190, 246, 90, 246,
    //     90, 150, 239, 238, 218, 91, 238, 242, 178, 55, 95, 215, 38, 94, 199, 44,
    //     189, 186, 193, 3, 40, 112, 112, 234, 120, 0, 114, 65, 234, 46, 58, 212,
    //     118, 172, 203, 195, 69, 142, 89, 20, 16, 187, 155, 142, 227, 66, 198,
    //     144, 154, 185, 228, 120, 82, 81, 136, 144, 92, 53, 110, 34, 172, 29,
    //     140, 98, 158, 254, 240, 132, 185, 200, 66, 31, 141, 188, 88, 204, 104,
    //     177, 38, 149, 217, 104, 243, 1, 100, 177, 161, 181, 20, 11, 96, 97, 136,
    //     167, 182, 53, 183, 41, 152, 222, 66, 230, 25, 15, 145, 132, 209, 109,
    //     90, 58, 91, 105, 39, 42, 233, 15, 223, 101, 5, 121, 74, 157, 161, 168,
    //     67, 46, 61, 157, 54, 151, 167, 115, 68, 225, 204, 233, 70, 28, 113, 70,
    //     66, 204, 231, 53, 33, 193, 23, 0, 28, 46, 166, 33, 223, 134, 52, 145,
    //     101, 84, 226, 81, 3, 253, 228, 37, 134, 187, 6, 149, 120, 204, 245, 45,
    //     129, 212, 190, 82, 176, 110, 154, 15, 194, 7, 78, 239, 56, 19, 70, 170,
    //     250, 49, 144, 60, 230, 50, 63, 9, 2, 44, 174, 205, 236, 71, 232, 115,
    //     211, 46, 104, 143, 190, 133, 138, 5, 116, 166, 11, 164, 59, 136, 83,
    //     152, 135, 89, 237, 113, 252, 235, 240, 95, 28, 203, 22, 170, 118, 150,
    //     29, 231, 120, 227, 232, 149, 188, 219, 36, 0, 84, 207, 174, 16, 135,
    //     240, 97, 93, 84, 126, 17, 193, 121, 164, 111, 74, 160, 88, 202, 133,
    //     141, 58, 212, 8, 131, 81, 183, 198, 253, 116, 18, 13, 198, 202, 86, 205,
    //     131, 196, 96, 32, 233, 154, 240, 113, 60, 248, 18, 214, 12, 238, 226,
    //     26, 70, 140, 95, 82, 162, 173, 25, 171, 248, 84, 89, 119, 232, 157, 227,
    //     9, 61, 161, 192, 206, 19, 124, 107, 119, 93, 173, 32, 80, 140, 194, 199,
    //     110, 226, 113, 96, 254, 125, 227, 4, 123, 229, 249, 40, 95, 82, 66, 33,
    //     226, 74, 222, 180, 244, 44, 103, 55, 221, 56, 195, 76, 189, 149, 227,
    //     205, 229, 44, 232, 73, 62, 57, 127, 42, 173, 110, 98, 151, 3, 144, 127,
    //     136, 147, 101, 229, 86, 3, 114, 186, 150, 126, 136, 188, 233, 103, 82,
    //     199, 57, 23, 57, 119, 232, 144, 255, 237, 49, 164, 161, 81, 117, 3, 108,
    //     248, 54, 115, 6, 143, 62, 22, 156, 18, 141, 186, 225, 73, 35, 40, 145,
    //     25, 203, 231, 183, 208, 118, 28, 17, 135, 36, 235, 157, 112, 53, 40, 78,
    //     40, 70, 19, 91, 63, 167, 145, 72, 254, 56, 82, 115, 252, 102, 89, 90,
    //     206, 9, 188, 8, 251, 84, 95, 252, 120, 107, 205, 238, 191, 197, 2, 68,
    //     28, 6, 192, 30, 215, 43, 45, 163, 100, 251, 206, 33, 227, 164, 23, 22,
    //     72, 29, 12, 146, 34, 186, 0, 51, 181, 167, 217, 108, 26, 207, 14, 60,
    //     232, 241, 89, 80, 158, 249, 230, 222, 249, 153, 29, 194, 163, 90, 97,
    //     134, 112, 31, 73, 10, 12, 126, 120, 169, 61, 242, 54, 190, 228, 193, 9,
    //     251, 213, 143, 177, 93, 1, 96, 63, 24, 117, 3, 128, 49, 174, 92, 51,
    //     105, 17, 226, 38, 112, 157, 152, 82, 58, 239, 92, 29, 202, 205, 163, 14,
    //     52, 88, 62, 23, 161, 92, 122, 230, 49, 29, 43, 225, 125, 83, 221, 232,
    //     158, 17, 206, 123, 237, 140, 46, 29, 133, 63, 102, 221, 145, 98, 36, 11,
    //     36, 115, 226, 81, 125, 40, 237, 92, 95, 23, 36, 30, 247, 250, 75, 251,
    //     48, 114, 241, 33, 0, 151, 102, 16, 106, 166, 80, 53, 136, 199, 38, 0,
    //     216, 31, 27, 23, 160, 49, 168, 151, 99, 112, 53, 166, 163, 87, 215, 201,
    //     131, 120, 179, 240, 61, 112, 58, 95, 50, 224, 176, 142, 230, 128, 46, 3,
    //     191, 85, 198, 39, 168, 249, 41, 22, 168, 151, 88, 72, 219, 59, 127, 200,
    //     76, 113, 76, 216, 79, 27, 226, 181, 18, 66, 179, 50, 20, 235, 173, 9,
    //     155, 114, 182, 149, 110, 73, 175, 153, 174, 16, 118, 93, 151, 72, 188,
    //     208, 130, 185, 173, 231, 187, 219, 109, 242, 39, 241, 92, 57, 231, 232,
    //     78, 2, 120, 117, 252, 164, 13, 171, 105, 89, 161, 155, 34, 185, 44, 16,
    //     241, 83, 54, 200, 101, 42, 21, 6, 94, 119, 176, 201, 39, 84, 36, 98, 61,
    //     9,
    //   ])
    // );

    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverZkAuth = new ServerZkAuthOperations(serverSecretParams);

    // CLIENT
    const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assert(
      deepEqual(
        groupSecretParams.getMasterKey().serialized,
        masterKey.serialized
      ),
      "Group secret params is not equal to master key"
    );

    const groupPublicParams = groupSecretParams.getPublicParams();

    // SERVER
    // Issue credential
    const authCredentialResponse =
      serverZkAuth.issueAuthCredentialWithPniAsServiceIdWithRandom(
        TEST_ARRAY_32_2,
        aci,
        pni,
        redemptionTime
      );

    // const authCredentialResponse = new AuthCredentialWithPniResponse(
    //   new Uint8Array([
    //     0, 55, 232, 222, 134, 89, 125, 216, 138, 45, 250, 251, 42, 169, 74, 51,
    //     114, 121, 119, 243, 233, 150, 23, 240, 40, 183, 211, 187, 77, 163, 156,
    //     23, 10, 224, 111, 179, 229, 42, 179, 107, 61, 70, 83, 215, 231, 70, 248,
    //     14, 83, 176, 40, 47, 212, 10, 227, 115, 90, 132, 145, 222, 94, 12, 189,
    //     254, 123, 236, 50, 23, 193, 224, 112, 110, 159, 108, 109, 201, 137, 83,
    //     112, 107, 73, 9, 209, 156, 82, 117, 177, 142, 167, 70, 0, 135, 210, 94,
    //     236, 183, 110, 64, 1, 0, 0, 0, 0, 0, 0, 219, 146, 23, 72, 147, 239, 214,
    //     48, 76, 132, 142, 22, 119, 56, 237, 193, 99, 86, 228, 81, 116, 218, 34,
    //     170, 9, 178, 145, 163, 34, 201, 1, 12, 160, 132, 255, 92, 49, 130, 173,
    //     235, 88, 211, 61, 38, 43, 188, 152, 17, 179, 120, 179, 153, 155, 128,
    //     104, 96, 167, 246, 133, 54, 32, 68, 207, 12, 98, 206, 229, 228, 43, 217,
    //     125, 94, 87, 207, 128, 42, 161, 39, 56, 34, 74, 184, 94, 49, 243, 214,
    //     69, 231, 179, 173, 76, 23, 65, 55, 173, 1, 76, 77, 143, 24, 253, 84,
    //     142, 44, 20, 1, 246, 216, 105, 187, 42, 44, 20, 130, 176, 7, 129, 33,
    //     250, 75, 246, 28, 246, 56, 44, 190, 178, 5, 211, 247, 255, 201, 202,
    //     212, 66, 155, 0, 44, 76, 103, 21, 238, 96, 153, 131, 81, 26, 199, 3,
    //     186, 55, 206, 82, 108, 67, 227, 51, 242, 190, 4, 177, 63, 140, 39, 191,
    //     53, 38, 123, 2, 122, 1, 169, 58, 252, 126, 63, 89, 18, 42, 11, 203, 114,
    //     189, 64, 249, 141, 44, 89, 225, 115, 118, 15, 216, 216, 133, 253, 46,
    //     235, 82, 144, 203, 150, 48, 169, 65, 114, 19, 53, 158, 94, 227, 110,
    //     174, 225, 242, 190, 224, 186, 9, 20, 26, 146, 228, 9, 127, 165, 51, 228,
    //     81, 169, 149, 95, 81, 18, 238, 145, 150, 17, 197, 226, 30, 118, 113,
    //     204, 194, 184, 183, 8, 181, 155, 223, 253, 249, 174, 196, 9, 63, 246,
    //     194, 162, 208, 144, 162, 200, 154, 165, 178, 255, 25, 101, 7, 107, 225,
    //     238, 108, 202, 15, 138, 56, 1, 176, 8, 64, 252, 223, 222, 149, 11, 81,
    //     121, 133, 114, 182, 252, 222, 45, 173, 123, 254, 150, 252, 108, 249, 38,
    //     177, 173, 112, 128, 214, 202, 211, 189, 75, 91, 124, 12, 101, 91, 43, 8,
    //   ])
    // );

    // CLIENT
    // Receive credential
    const clientZkAuthCipher = new ClientZkAuthOperations(serverPublicParams);
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);

    const authCredential =
      clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(
        aci,
        pni,
        redemptionTime,
        authCredentialResponse
      );

    // Create and decrypt user entry
    const aciCiphertext = clientZkGroupCipher.encryptServiceId(aci);
    const aciPlaintext = clientZkGroupCipher.decryptServiceId(aciCiphertext);
    assert(aci.isEqual(aciPlaintext));
    const pniCiphertext = clientZkGroupCipher.encryptServiceId(pni);
    const pniPlaintext = clientZkGroupCipher.decryptServiceId(pniCiphertext);
    assert(pni.isEqual(pniPlaintext));

    // Create presentation
    const presentation =
      clientZkAuthCipher.createAuthCredentialWithPniPresentationWithRandom(
        TEST_ARRAY_32_5,
        groupSecretParams,
        authCredential
      );

    // Verify presentation
    assert(
      deepEqual(
        aciCiphertext.serialized,
        presentation.getUuidCiphertext().serialized
      )
    );
    const presentationPniCiphertext = presentation.getPniCiphertext();
    // Use a generic assertion instead of assert.isNotNull because TypeScript understands it.
    assert(presentationPniCiphertext !== null);

    assert(
      deepEqual(pniCiphertext.serialized, presentationPniCiphertext?.serialized)
    );

    assert(
      deepEqual(
        presentation.getRedemptionTime(),
        new Date(1000 * redemptionTime)
      )
    );

    serverZkAuth.verifyAuthCredentialPresentation(
      groupPublicParams,
      presentation,
      new Date(1000 * redemptionTime)
    );
  });

  test("Test Auth Zkc Integration", async () => {
    const aci = Aci.fromUuid(TEST_UUID);
    const pni = Pni.fromUuid(TEST_UUID_1);
    const redemptionTime = 123456 * SECONDS_PER_DAY;

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams =
      ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverZkAuth = new ServerZkAuthOperations(serverSecretParams);

    // CLIENT
    const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    assert(
      deepEqual(
        groupSecretParams.getMasterKey().serialized,
        masterKey.serialized
      )
    );

    const groupPublicParams = groupSecretParams.getPublicParams();

    // SERVER
    // Issue credential
    const authCredentialResponse =
      serverZkAuth.issueAuthCredentialWithPniZkcWithRandom(
        TEST_ARRAY_32_2,
        aci,
        pni,
        redemptionTime
      );

    // CLIENT
    // Receive credential
    const clientZkAuthCipher = new ClientZkAuthOperations(serverPublicParams);
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    const authCredential =
      clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(
        aci,
        pni,
        redemptionTime,
        authCredentialResponse
      );

    // Create and decrypt user entry
    const aciCiphertext = clientZkGroupCipher.encryptServiceId(aci);
    const aciPlaintext = clientZkGroupCipher.decryptServiceId(aciCiphertext);
    assert(aci.isEqual(aciPlaintext));
    const pniCiphertext = clientZkGroupCipher.encryptServiceId(pni);
    const pniPlaintext = clientZkGroupCipher.decryptServiceId(pniCiphertext);
    assert(pni.isEqual(pniPlaintext));

    // Create presentation
    const presentation =
      clientZkAuthCipher.createAuthCredentialWithPniPresentationWithRandom(
        TEST_ARRAY_32_5,
        groupSecretParams,
        authCredential
      );

    // Verify presentation
    assert(
      deepEqual(
        aciCiphertext.serialized,
        presentation.getUuidCiphertext().serialized
      )
    );
    const presentationPniCiphertext = presentation.getPniCiphertext();
    // Use a generic assertion instead of assert.isNotNull because TypeScript understands it.
    assert(presentationPniCiphertext !== null);

    assert(
      deepEqual(pniCiphertext.serialized, presentationPniCiphertext?.serialized)
    );
    assert(
      deepEqual(
        presentation.getRedemptionTime(),
        new Date(1000 * redemptionTime)
      )
    );

    serverZkAuth.verifyAuthCredentialPresentation(
      groupPublicParams,
      presentation,
      new Date(1000 * redemptionTime)
    );
  });

  test("Test expiring profile key integration", () => {
    const userId = Aci.fromUuid(TEST_UUID);

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    const serverSecretParams =
      ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
    const serverPublicParams = serverSecretParams.getPublicParams();
    const serverZkProfile = new ServerZkProfileOperations(serverSecretParams);

    // CLIENT
    const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    const groupPublicParams = groupSecretParams.getPublicParams();
    const clientZkProfileCipher = new ClientZkProfileOperations(
      serverPublicParams
    );

    const profileKey = new ProfileKey(TEST_ARRAY_32_1);
    const profileKeyCommitment = profileKey.getCommitment(userId);

    // Create context and request
    const context =
      clientZkProfileCipher.createProfileKeyCredentialRequestContextWithRandom(
        TEST_ARRAY_32_3,
        userId,
        profileKey
      );
    const request = context.getRequest();

    // SERVER
    const now = Math.floor(Date.now() / 1000);
    const startOfDay = now - (now % SECONDS_PER_DAY);
    const expiration = startOfDay + 5 * SECONDS_PER_DAY;
    const response =
      serverZkProfile.issueExpiringProfileKeyCredentialWithRandom(
        TEST_ARRAY_32_4,
        request,
        userId,
        profileKeyCommitment,
        expiration
      );

    // CLIENT
    // Gets stored profile credential
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);
    const profileKeyCredential =
      clientZkProfileCipher.receiveExpiringProfileKeyCredential(
        context,
        response
      );

    // Create encrypted UID and profile key
    const uuidCiphertext = clientZkGroupCipher.encryptServiceId(userId);
    const plaintext = clientZkGroupCipher.decryptServiceId(uuidCiphertext);
    assert(plaintext.isEqual(userId));

    const profileKeyCiphertext = clientZkGroupCipher.encryptProfileKey(
      profileKey,
      userId
    );
    const decryptedProfileKey = clientZkGroupCipher.decryptProfileKey(
      profileKeyCiphertext,
      userId
    );

    assert(deepEqual(profileKey.serialized, decryptedProfileKey.serialized));
    assert(
      deepEqual(
        profileKeyCredential.getExpirationTime(),
        new Date(expiration * 1000)
      )
    );

    const presentation =
      clientZkProfileCipher.createExpiringProfileKeyCredentialPresentationWithRandom(
        TEST_ARRAY_32_5,
        groupSecretParams,
        profileKeyCredential
      );

    // Verify presentation
    serverZkProfile.verifyProfileKeyCredentialPresentation(
      groupPublicParams,
      presentation
    );
    serverZkProfile.verifyProfileKeyCredentialPresentation(
      groupPublicParams,
      presentation,
      new Date(expiration * 1000 - 5)
    );

    const uuidCiphertextRecv = presentation.getUuidCiphertext();

    assert(deepEqual(uuidCiphertext.serialized, uuidCiphertextRecv.serialized));

    if (Platform.OS == "android") {
      //Test expiration
      assert(
        throwsSync(() =>
          serverZkProfile.verifyProfileKeyCredentialPresentation(
            groupPublicParams,
            presentation,
            new Date(expiration * 1000)
          )
        )
      );

      assert(
        throwsSync(() =>
          serverZkProfile.verifyProfileKeyCredentialPresentation(
            groupPublicParams,
            presentation,
            new Date(expiration * 1000 + 5)
          )
        )
      );
    }
  });

  // test("Test server signatures", async () => {
  //     const serverSecretParams =
  //         ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
  //     const serverPublicParams = serverSecretParams.getPublicParams();

  //     const message = TEST_ARRAY_32_1;

  //     const signature = serverSecretParams.signWithRandom(
  //         TEST_ARRAY_32_2,
  //         message
  //     );
  //     serverPublicParams.verifySignature(message, signature);
  //     assert(deepEqual(
  //         new Uint8Array(Buffer.from('87d354564d35ef91edba851e0815612e864c227a0471d50c270698604406d003a55473f576cf241fc6b41c6b16e5e63b333c02fe4a33858022fdd7a4ab367b06', 'base64')),
  //         signature.serialized,
  //     ),
  //     `you should have gotten
  //     ${signature.serialized}
  //     but you got
  //     ${new Uint8Array(Buffer.from('87d354564d35ef91edba851e0815612e864c227a0471d50c270698604406d003a55473f576cf241fc6b41c6b16e5e63b333c02fe4a33858022fdd7a4ab367b06', 'base64'))}`);
  //     const alteredMessage = new Uint8Array(Buffer.from(message));
  //     alteredMessage[0] ^= 1;

  //     assert(!deepEqual(message, alteredMessage), "Message was not altered");

  //     assert(
  //       throwsSync(() =>
  //         serverPublicParams.verifySignature(alteredMessage, signature)
  //       ),
  //       "Altered message was verified"
  //     );
  // })

  // test("testGroupIdentifier", () => {
  //   const groupSecretParams = GroupSecretParams.generateWithRandom(TEST_ARRAY_32);
  //   const groupPublicParams = groupSecretParams.getPublicParams();

  //   console.log(">><M><><><> group public params length", groupPublicParams.getGroupIdentifier().contents.length)
  //   console.log("><><M><><<>< expectedt length", hexToBuffer('31f2c60f86f4c5996e9e2568355591d9').length)

  //   assert(deepEqual(
  //     hexToBuffer('31f2c60f86f4c5996e9e2568355591d9'),
  //     groupPublicParams.getGroupIdentifier().contents
  //   ),
  // `you should have gotten
  // ${groupPublicParams.getGroupIdentifier().contents}
  // but you got
  // ${new Uint8Array(Buffer.from('31f2c60f86f4c5996e9e2568355591d9', 'hex'))}
  // `);
  // }
  // );

  // test("testInvalidSerialized", () => {
  //   const ckp = Buffer.alloc(289);
  //   ckp.fill(-127);
  //   assert(throwsSync(() => new GroupSecretParams(ckp)),
  //   "Invalid serialized group secret params did not throw an error"
  // );
  // })

  // test("testWrongSizeSerialized", () => {
  //   const ckp = Buffer.alloc(5);
  //   ckp.fill(-127);
  //   assert(throwsSync(() => new GroupSecretParams(ckp)),
  //   "wrong sized serialized group secret params did not throw an error");
  // })
  test("Test Blob Encryption", () => {
    const groupSecretParams = GroupSecretParams.generate();
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);

    const plaintext = new Uint8Array(Buffer.from([0, 1, 2, 3, 4]));
    const ciphertext = clientZkGroupCipher.encryptBlob(plaintext);
    const plaintext2 = clientZkGroupCipher.decryptBlob(ciphertext);
    assert(deepEqual(plaintext, plaintext2));
  });

  test("Test Blob Encription with random", () => {
    const groupSecretParams = GroupSecretParams.generate();
    const clientZkGroupCipher = new ClientZkGroupCipher(groupSecretParams);

    const plaintext = new Uint8Array(Buffer.from([0, 1, 2, 3, 4]));
    const ciphertext = clientZkGroupCipher.encryptBlobWithRandom(
      TEST_ARRAY_32,
      plaintext
    );
    const plaintext2 = clientZkGroupCipher.decryptBlob(ciphertext);
    assert(deepEqual(plaintext, plaintext2));
  });

  test("Test Derive Profile Key", () => {
    const expectedAccessKey = hexToBuffer("5a723acee52c5ea02b92a3a360c09595");
    const profileKey = new Uint8Array(Buffer.alloc(32, 0x02));

    const result = new ProfileKey(profileKey).deriveAccessKey();
    assert(deepEqual(expectedAccessKey, result));
  });

  test("GroupSendEndorsement", () => {
    const serverSecretParams =
      ServerSecretParams.generateWithRandom(TEST_ARRAY_32);
    const serverPublicParams = serverSecretParams.getPublicParams();

    const aliceAci = Aci.parseFromServiceIdString(
      "9d0652a3-dcc3-4d11-975f-74d61598733f"
    );
    const bobAci = Aci.parseFromServiceIdString(
      "6838237d-02f6-4098-b110-698253d15961"
    );
    const eveAci = Aci.parseFromServiceIdString(
      "3f0f4734-e331-4434-bd4f-6d8f6ea6dcc7"
    );
    const malloryAci = Aci.parseFromServiceIdString(
      "5d088142-6fd7-4dbd-af00-fdda1b3ce988"
    );

    const masterKey = new GroupMasterKey(TEST_ARRAY_32_1);
    const groupSecretParams = GroupSecretParams.deriveFromMasterKey(masterKey);

    const aliceCiphertext = new ClientZkGroupCipher(
      groupSecretParams
    ).encryptServiceId(aliceAci);
    const groupCiphertexts = [aliceAci, bobAci, eveAci, malloryAci].map(
      (next) =>
        new ClientZkGroupCipher(groupSecretParams).encryptServiceId(next)
    );

    // Server
    const now = Math.floor(Date.now() / 1000);
    const startOfDay = now - (now % SECONDS_PER_DAY);
    const expiration = startOfDay + 2 * SECONDS_PER_DAY;
    const todaysKey = GroupSendDerivedKeyPair.forExpiration(
      new Date(1000 * expiration),
      serverSecretParams
    );
    const response = GroupSendEndorsementsResponse.issue(
      groupCiphertexts,
      todaysKey
    );

    // Client
    const receivedEndorsements = response.receiveWithServiceIds(
      [aliceAci, bobAci, eveAci, malloryAci],
      aliceAci,
      groupSecretParams,
      serverPublicParams
    );
    // Missing local user

    assert(
      throwsSync(() =>
        response.receiveWithServiceIds(
          [bobAci, eveAci, malloryAci],
          aliceAci,
          groupSecretParams,
          serverPublicParams
        )
      ),
      "Missing local user"
    );
    // Missing another user
    assert(
      throwsSync(() =>
        response.receiveWithServiceIds(
          [aliceAci, eveAci, malloryAci],
          aliceAci,
          groupSecretParams,
          serverPublicParams
        )
      ),
      "Missing another user"
    );

    // Try the other receive too
    {
      const receivedEndorsementsAlternate = response.receiveWithCiphertexts(
        groupCiphertexts,
        aliceCiphertext,
        serverPublicParams
      );
      assert(
        deepEql(
          receivedEndorsements.combinedEndorsement.serialized,
          receivedEndorsementsAlternate.combinedEndorsement.serialized
        )
      );

      // Missing local user
      assert(
        throwsSync(() =>
          response.receiveWithCiphertexts(
            groupCiphertexts.slice(1),
            aliceCiphertext,
            serverPublicParams
          )
        ),
        "Missing local user"
      );
      // Missing another user

      assert(
        throwsSync(() =>
          response.receiveWithCiphertexts(
            groupCiphertexts.slice(0, -1),
            aliceCiphertext,
            serverPublicParams
          )
        ),
        "Missing another user"
      );
    }

    const combinedToken =
      receivedEndorsements.combinedEndorsement.toToken(groupSecretParams);
    const fullCombinedToken = combinedToken.toFullToken(
      response.getExpiration()
    );

    // SERVER
    // Verify token
    const verifyKey = GroupSendDerivedKeyPair.forExpiration(
      fullCombinedToken.getExpiration(),
      serverSecretParams
    );

    fullCombinedToken.verify([bobAci, eveAci, malloryAci], verifyKey);
    fullCombinedToken.verify(
      [bobAci, eveAci, malloryAci],
      verifyKey,
      new Date(1000 * (now + 60 * 60))
    ); // one hour from now

    // Included extra user
    assert(
      throwsSync(() =>
        fullCombinedToken.verify(
          [aliceAci, bobAci, eveAci, malloryAci],
          verifyKey
        )
      ),
      "Included extra user"
    );
    // Missing user

    assert(
      throwsSync(() =>
        fullCombinedToken.verify([eveAci, malloryAci], verifyKey)
      ),
      "Missing user"
    );
    // Expired
    assert(
      throwsSync(() =>
        fullCombinedToken.verify(
          [bobAci, eveAci, malloryAci],
          verifyKey,
          new Date(1000 * (expiration + 1))
        )
      ),
      "Expired"
    );

    // Excluding a user
    {
      // CLIENT
      const everybodyButMallory =
        receivedEndorsements.combinedEndorsement.byRemoving(
          receivedEndorsements.endorsements[3]
        );
      const fullEverybodyButMalloryToken = everybodyButMallory.toFullToken(
        groupSecretParams,
        response.getExpiration()
      );

      // SERVER
      const everybodyButMalloryKey = GroupSendDerivedKeyPair.forExpiration(
        fullEverybodyButMalloryToken.getExpiration(),
        serverSecretParams
      );

      fullEverybodyButMalloryToken.verify(
        [bobAci, eveAci],
        everybodyButMalloryKey
      );

      // Custom combine
      {
        // CLIENT

        const bobAndEve = GroupSendEndorsement.combine([
          receivedEndorsements.endorsements[1],
          receivedEndorsements.endorsements[2],
        ]);

        const fullBobAndEveToken = bobAndEve.toFullToken(
          groupSecretParams,
          response.getExpiration()
        );
        // SERVER
        const bobAndEveKey = GroupSendDerivedKeyPair.forExpiration(
          fullBobAndEveToken.getExpiration(),
          serverSecretParams
        );

        fullBobAndEveToken.verify([bobAci, eveAci], bobAndEveKey);
      }

      // Single-user
      {
        // CLIENT
        const bobEndorsement = receivedEndorsements.endorsements[1];
        const fullBobToken = bobEndorsement.toFullToken(
          groupSecretParams,
          response.getExpiration()
        );

        // SERVER
        const bobKey = GroupSendDerivedKeyPair.forExpiration(
          fullBobToken.getExpiration(),
          serverSecretParams
        );

        fullBobToken.verify([bobAci], bobKey);
      }
    }
  });
};
