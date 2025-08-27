package vjwt

import (
	"log"
	"testing"
	"time"
	// "time"
)

type User struct {
	UID  int64  `json:"uid"`
	Name string `json:"name"`
}

func TestJwt(t *testing.T) {
	vjwt := NewJwt[User](&VjwtP{
		Key: "helloword",
	})
	token, exp, err := vjwt.Token(&User{
		UID:  1,
		Name: "张三",
	})
	if err != nil {
		t.Fatal(err)
	}
	log.Print(token, exp, err)
}

func TestJwtValid(t *testing.T) {
	vjwt := NewJwt[User](&VjwtP{
		Key:    "helloword",
		MaxAge: 2 * time.Second,
	})
	token, _, err := vjwt.Token(&User{
		UID:  1,
		Name: "张三",
	})
	if err != nil {
		t.Fatal(err)
	}

	jc, err := vjwt.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	log.Print(string(jc.Token))
	log.Print(jc.StandardClaims.Expiry)

	// 错误的token
	_, err = vjwt.Verify(token)
	if err == nil {
		t.Fatal()
	}
	log.Print(err)

	// 过期的token
	time.Sleep(3 * time.Second)
	_, err = vjwt.Verify(token)
	if err == nil {
		t.Fatal()
	}
	log.Print(err)

}

func TestJwtBlockValid(t *testing.T) {
	vjwt := NewJwt[User](&VjwtP{
		Key: "helloword",
	})
	token, _, err := vjwt.Token(&User{
		UID:  1,
		Name: "张三",
	})
	if err != nil {
		t.Fatal(err)
	}

	log.Print(token, err)

	jc, err := vjwt.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	log.Print(string(jc.Token))
	log.Print(jc.StandardClaims.Expiry)

	// 模拟注销后，对token进行拉黑
	if err := vjwt.Block(token); err != nil {
		t.Fatal(err)
	}
	// 再次验证
	_, err = vjwt.Verify(token)
	if err == nil {
		t.Fail()
	}

	log.Print(err)

}

func TestJwtRefer(t *testing.T) {
	vjwt := NewJwt[User](&VjwtP{
		Key: "helloword",
	})
	token, _, err := vjwt.Token(&User{
		UID:  1,
		Name: "张三",
	})
	if err != nil {
		t.Fatal(err)
	}

	log.Print(token, err)

	jc, err := vjwt.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	log.Print(string(jc.Token))
	log.Print(jc.StandardClaims.Expiry)

	time.Sleep(3 * time.Second)

	// 刷新jwt
	rtoken, exp, err := vjwt.ReferToken(token, &User{})

	log.Print(rtoken, exp, err)
	// 对token重新验证旧的
	_, err = vjwt.Verify(token)
	if err != nil {
		t.Fatal()
	}
	rc, err := vjwt.Verify(rtoken)
	if err != nil {
		t.Fatal()
	}
	log.Print(string(rc.Token), rc.StandardClaims.Expiry)
}

type uc struct {
	UID   int64
	Uname string
}

func TestUcJwtRefer(t *testing.T) {
	vjwt := NewJwt[uc](&VjwtP{
		Key: "helloword",
	})
	token, _, err := vjwt.Token(&uc{
		UID:   1,
		Uname: "张三",
	})
	if err != nil {
		t.Fatal(err)
	}

	log.Print(token, err)

	jc, err := vjwt.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	log.Print(string(jc.Token))
	log.Print(jc.StandardClaims.Expiry)

	time.Sleep(3 * time.Second)

	// 刷新jwt
	rtoken, exp, err := vjwt.ReferToken(token, &uc{})

	log.Print(rtoken, exp, err)
	// 对token重新验证旧的
	_, err = vjwt.Verify(token)
	if err != nil {
		t.Fatal()
	}
	rc, err := vjwt.Verify(rtoken)
	if err != nil {
		t.Fatal()
	}
	log.Print(string(rc.Token), rc.StandardClaims.Expiry)
}
