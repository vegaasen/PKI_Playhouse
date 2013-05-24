package com.vegaasen.playhouse.model;

import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="vegard.aasen@telenor.com">Vegard Aasen</a>
 */
public final class Result {

    private static final String separator = ",", newLine = "\n";

    private static final String EMPTY = "";
    private Date initiated;
    private long nanoResult;
    private Date finished;
    private String documentUsed;
    private String callingMethod;
    private int numOfIterations;
    private int numOfThreads;

    private Result(Builder builder) {
        this.initiated = builder.initiated;
        this.nanoResult = builder.nanoResult;
        this.finished = builder.finished;
        this.documentUsed = builder.documentUsed;
        this.callingMethod = builder.callingMethod;
        this.numOfIterations = builder.numOfIterations;
        this.numOfThreads = builder.numOfThreads;
    }

    public Date getInitiated() {
        return initiated;
    }

    public long getNanoResult() {
        return nanoResult;
    }

    public Date getFinished() {
        return finished;
    }

    public String getDocumentUsed() {
        return documentUsed;
    }

    public String getCallingMethod() {
        return callingMethod;
    }

    public int getNumOfIterations() {
        return numOfIterations;
    }

    public int getNumOfThreads() {
        return numOfThreads;
    }

    public static String generateResultSetString(Result r, int num) {
        if (r != null) {
            StringBuilder builder = new StringBuilder();
            builder.append(String.format("%s)%s", num, separator));
            builder.append(r.getInitiated());
            builder.append(separator);
            builder.append(r.getFinished());
            builder.append(separator);
            builder.append(r.getNumOfIterations());
            builder.append(separator);
            builder.append(r.getNumOfThreads());
            builder.append(separator);
            builder.append(String.format("%sns%s%sms%s%ss",
                    r.getNanoResult(),
                    separator,
                    (double) TimeUnit.NANOSECONDS.toMillis(r.getNanoResult()),
                    separator,
                    (double) TimeUnit.NANOSECONDS.toSeconds(r.getNanoResult())
            ));
            builder.append(separator);
            builder.append(r.getCallingMethod());
            builder.append(separator);
            builder.append(r.getDocumentUsed());
            builder.append(newLine);
            return builder.toString();
        }
        return EMPTY;
    }

    public static String generateResultSetString(List<Result> results) {
        if (results != null && !results.isEmpty()) {
            StringBuilder builder = new StringBuilder();
            builder.append("");
            int num = 1;
            builder.append("#");
            builder.append(separator);
            builder.append("Initiated");
            builder.append(separator);
            builder.append("Finished");
            builder.append(separator);
            builder.append("# of Iterations");
            builder.append(separator);
            builder.append("# of Threads");
            builder.append(separator);
            builder.append("Nanos");
            builder.append(separator);
            builder.append("Millis");
            builder.append(separator);
            builder.append("Secs");
            builder.append(separator);
            builder.append("Method");
            builder.append(separator);
            builder.append("Document location");
            builder.append(newLine);
            for (Result r : results) {
                builder.append(generateResultSetString(r, num));
                num++;
            }
            return builder.toString();
        }
        return EMPTY;
    }

    public static class Builder {
        private Date initiated = null;
        private long nanoResult = 0;
        private Date finished = null;
        private String documentUsed = "";
        private String callingMethod = "";
        private int numOfIterations = 0;
        private int numOfThreads = 1;

        public Builder() {

        }

        public Builder initiated(Date date) {
            initiated = date;
            return this;
        }

        public Builder nanoResult(long res) {
            nanoResult = res;
            return this;
        }

        public Builder finished(Date fin) {
            finished = fin;
            return this;
        }

        public Builder documentUsed(String s) {
            documentUsed = s;
            return this;
        }

        public Builder callingMethod(String s) {
            callingMethod = s;
            return this;
        }

        public Builder numOfIterations(int i) {
            numOfIterations = i;
            return this;
        }

        public Builder numOfThreads(int i) {
            numOfThreads = i;
            return this;
        }

        public Result build() {
            return new Result(this);
        }

    }

}