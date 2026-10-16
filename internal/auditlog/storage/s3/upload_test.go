package s3_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	awsS3 "github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.containerssh.io/containerssh/config"
	auditLogStorage "go.containerssh.io/containerssh/internal/auditlog/storage"
	"go.containerssh.io/containerssh/internal/auditlog/storage/s3"
	"go.containerssh.io/containerssh/internal/test"
	"go.containerssh.io/containerssh/log"
)

func newTestStorage(t *testing.T) auditLogStorage.ReadWriteStorage {
	t.Helper()
	s3Service := test.S3(t)
	bucket := "auditlog"
	require.NoError(t, setupS3(
		s3Service.AccessKey(), s3Service.SecretKey(), s3Service.URL(), s3Service.Region(), bucket,
	))

	storage, err := s3.NewStorage(
		config.AuditLogS3Config{
			Local:           t.TempDir(),
			AccessKey:       s3Service.AccessKey(),
			SecretKey:       s3Service.SecretKey(),
			Bucket:          bucket,
			Region:          s3Service.Region(),
			Endpoint:        s3Service.URL(),
			PathStyleAccess: s3Service.PathStyle(),
			UploadPartSize:  5 * 1024 * 1024,
			ParallelUploads: 20,
			Metadata:        config.AuditLogS3Metadata{},
		},
		log.NewTestLogger(t),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		storage.Shutdown(context.Background())
	})
	return storage
}

func setupS3(accessKey string, secretKey string, endpoint string, region string, bucket string) error {
	awsConfig := &aws.Config{
		CredentialsChainVerboseErrors: nil,
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{
			Value: credentials.Value{
				AccessKeyID:     accessKey,
				SecretAccessKey: secretKey,
			},
		}),
		Endpoint:         aws.String(endpoint),
		Region:           aws.String(region),
		S3ForcePathStyle: aws.Bool(true),
	}
	sess := session.Must(session.NewSession(awsConfig))
	s3Connection := awsS3.New(sess)
	if _, err := s3Connection.CreateBucket(&awsS3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		return err
	}
	return nil
}

func getS3Objects(t *testing.T, storage auditLogStorage.ReadWriteStorage) []auditLogStorage.Entry {
	var objects []auditLogStorage.Entry
	objectChan, errChan := storage.List()
	for {
		finished := false
		select {
		case object, ok := <-objectChan:
			if !ok {
				finished = true
				break
			}
			objects = append(objects, object)
		case err, ok := <-errChan:
			if !ok {
				finished = true
				break
			}
			assert.Fail(t, "error while fetching objects from object storage", err)
		}
		if finished {
			break
		}
	}
	return objects
}

func waitForS3Objects(t *testing.T, storage auditLogStorage.ReadWriteStorage, count int) []auditLogStorage.Entry {
	tries := 0
	var objects []auditLogStorage.Entry
	for {
		if tries > 10 {
			break
		}
		objects = getS3Objects(t, storage)
		if len(objects) > count-1 {
			break
		} else {
			tries++
			time.Sleep(10 * time.Second)
		}
	}
	return objects
}

func TestSmallUpload(t *testing.T) {
	if testing.Short() {
		t.Skipf("skipping test in short mode")
	}
	storage := newTestStorage(t)

	writer, err := storage.OpenWriter("test")
	if err != nil {
		assert.Fail(t, "failed to open storage writer (%v)", err)
		return
	}
	var data = []byte("Hello world!")
	if _, err := writer.Write(data); err != nil {
		assert.Fail(t, "failed to write to storage writer (%v)", err)
		return
	}
	if err := writer.Close(); err != nil {
		assert.Fail(t, "failed to close storage writer (%v)", err)
		return
	}

	storage.Shutdown(context.Background())

	objects := waitForS3Objects(t, storage, 1)
	assert.Equal(t, 1, len(objects))

	r, err := storage.OpenReader(objects[0].Name)
	if err != nil {
		assert.Fail(t, "failed to open reader for recently stored object", err)
		return
	}
	d, err := io.ReadAll(r)
	if err != nil {
		assert.Fail(t, "failed to open read from S3", err)
		return
	}

	assert.Equal(t, data, d)
}

func TestLargeUpload(t *testing.T) {
	if testing.Short() {
		t.Skipf("skipping test in short mode")
	}
	storage := newTestStorage(t)

	writer, err := storage.OpenWriter("test")
	if err != nil {
		assert.Fail(t, "failed to open storage writer (%v)", err)
		return
	}
	size := 25 * 1000 * 1000
	var data = []byte("0123456789")
	for i := 0; i < size/len(data); i++ {
		if _, err := writer.Write(data); err != nil {
			assert.Fail(t, "failed to write to storage writer (%v)", err)
			return
		}
	}
	if err := writer.Close(); err != nil {
		assert.Fail(t, "failed to close storage writer (%v)", err)
		return
	}

	storage.Shutdown(context.Background())

	objects := waitForS3Objects(t, storage, 1)
	assert.Equal(t, 1, len(objects))

	r, err := storage.OpenReader(objects[0].Name)
	if err != nil {
		assert.Fail(t, "failed to open reader for recently stored object", err)
		return
	}
	d, err := io.ReadAll(r)
	if err != nil {
		assert.Fail(t, "failed to open read from S3", err)
		return
	}

	assert.Equal(t, size, len(d))
}
