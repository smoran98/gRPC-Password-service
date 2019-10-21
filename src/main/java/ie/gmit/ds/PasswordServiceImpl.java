package ie.gmit.ds;

import com.google.protobuf.BoolValue;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;

public class PasswordServiceImpl extends PasswordServiceGrpc.PasswordServiceImplBase {

    @Override
    public void hash(HashInput request, StreamObserver<HashOutput> responseObserver) {

        byte[] salt = Passwords.getNextSalt();
        byte[] hashed = Passwords.hash(request.getPassword().toCharArray(), salt);

        HashOutput output = HashOutput.newBuilder()
                .setSalt(ByteString.copyFrom(salt))
                .setUserId(request.getUserId())
                .setHashedPassword(ByteString.copyFrom(hashed))
                .build();

        responseObserver.onNext(output);
        responseObserver.onCompleted();
    }

    @Override
    public void validate(ValidateInput request, StreamObserver<BoolValue> responseObserver) {
        byte[] salt = request.getSalt().toByteArray();
        char[] password = request.getPassword().toCharArray();
        byte[] expectedHash = request.getHashedPassword().toByteArray();

        boolean result = Passwords.isExpectedPassword(password,salt,expectedHash);

        responseObserver.onNext(BoolValue.of(result));
        responseObserver.onCompleted();
    }
}
