# Makefile for コンパイル確認

# マクロ定義
CC	= csc
CFLAGS	= /nologo
LDFLAGS	= 
INCLUDES = 
LIBS	= \
	".\BinUtil.cs" \
	".\DumpLib.cs"
TARGET	= *.cs
OBJS	= 


# 生成規則
all:
	$(CC) $(CFLAGS) /d:UTEST CapWrite.cs
	$(CC) $(CFLAGS) /d:CAPREAD_UTEST CapRead.cs $(LIBS)


###
### makeの基本操作
### 	$make ルールorオブジェクト
###
### Makefileの中身
### ルール	: 依存ファイル(生成するオブジェクト等)
###
### オブジェクト: 依存ファイル
### 		コマンド(リンク操作等)
###
### .c.o:	# サフィックス「～.c」から「～.o」を生成する
### 		コマンド(コンパイル操作等)
###
### マクロ定義
###  $<  -> サフィックスルールの対象名
###  $@  -> 対象名
###  $(マクロ名:文字列1=文字列2)   -> マクロ名の文字列1を2に置換する
###